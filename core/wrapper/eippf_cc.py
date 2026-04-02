#!/usr/bin/env python3
"""EIPPF compiler wrapper for gcc/g++/cl intent mapping and pass-plugin injection."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import PurePath
from typing import List, Optional, Sequence


Intent = str  # "gcc" | "g++" | "cl"

_KNOWN_COMPILER_NAMES = {
    "cc",
    "c++",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "clang-cl",
    "cl",
    "cl.exe",
    "cc.exe",
    "c++.exe",
    "gcc.exe",
    "g++.exe",
    "clang.exe",
    "clang++.exe",
    "clang-cl.exe",
}

_CXX_SOURCE_EXTENSIONS = {
    ".cc",
    ".cp",
    ".cxx",
    ".cpp",
    ".c++",
    ".cxxm",
    ".cppm",
    ".ixx",
    ".mm",
    ".hpp",
    ".hh",
    ".hxx",
}

_SOURCE_EXTENSIONS = _CXX_SOURCE_EXTENSIONS | {
    ".c",
    ".m",
    ".s",
    ".asm",
    ".ll",
}

_OBJECT_OR_LIBRARY_EXTENSIONS = {
    ".o",
    ".obj",
    ".a",
    ".lib",
    ".so",
    ".dylib",
}

_GNU_OPTIONS_WITH_VALUE = {
    "-o",
    "-x",
    "-I",
    "-D",
    "-U",
    "-include",
    "-imacros",
    "-isystem",
    "-isysroot",
    "-target",
    "-arch",
    "-MF",
    "-MT",
    "-MQ",
    "-L",
    "-B",
    "-Xclang",
    "-Xlinker",
    "-Xassembler",
    "-mllvm",
}

_MSVC_OPTIONS_WITH_VALUE = {
    "/fi",
    "/fo",
    "/fe",
    "/fd",
    "/fa",
    "/fp",
    "/ifcoutput",
    "/ifcsearchdir",
    "/i",
    "/d",
    "/u",
    "/external:i",
    "/winsysroot",
}

_MSVC_STYLE_EXACT = {
    "/c",
    "/e",
    "/ep",
    "/link",
    "/nologo",
    "/ld",
    "/tp",
    "/tc",
}

_MSVC_STYLE_PREFIX = (
    "/fo",
    "/fe",
    "/fi",
    "/fd",
    "/fa",
    "/fp",
    "/ifcoutput",
    "/ifcsearchdir",
    "/std:",
    "/eh",
    "/gr",
    "/md",
    "/mt",
    "/clang:",
    "/external:",
)

_STRIP_TOOL_WHITELIST = {"llvm-strip", "strip"}


@dataclass
class ParsedInvocation:
    pass_plugins: List[str]
    forced_compiler: Optional[str]
    compiler_command: List[str]
    strip_output: bool
    strip_mode: str
    strip_tool: Optional[str]
    strip_fail_closed: bool


@dataclass
class ForwardCommand:
    intent: Intent
    compiler_args: List[str]
    command: List[str]


def basename_lower(path: str) -> str:
    return PurePath(path).name.lower()


def non_empty_env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def env_bool(name: str, default: bool) -> bool:
    value = non_empty_env(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} expects a boolean value (0/1/true/false)")


def split_plugin_values(value: str) -> List[str]:
    raw_items = [item.strip() for item in value.split(os.pathsep)]
    return [item for item in raw_items if item]


def deduplicate_preserve_order(items: Sequence[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def intent_from_name(name: str) -> Optional[Intent]:
    lower_name = basename_lower(name)
    if lower_name in {"cl", "cl.exe", "clang-cl", "clang-cl.exe"}:
        return "cl"
    if "++" in lower_name:
        return "g++"
    if lower_name in {"gcc", "cc", "clang", "gcc.exe", "cc.exe", "clang.exe"}:
        return "gcc"
    return None


def looks_like_known_compiler(token: str) -> bool:
    if not token or token.startswith("-"):
        return False
    lower = basename_lower(token)
    if lower in _KNOWN_COMPILER_NAMES:
        return True

    core = lower[:-4] if lower.endswith(".exe") else lower
    for marker in ("gcc", "g++", "cc", "c++", "clang", "clang++", "clang-cl", "cl"):
        if core == marker:
            return True
        if core.endswith(f"-{marker}") or core.endswith(f"_{marker}"):
            return True
    return False


def contains_pass_plugin_flag(args: Sequence[str]) -> bool:
    return any(
        arg.startswith("-fpass-plugin=") or arg.startswith("/clang:-fpass-plugin=") for arg in args
    )


def has_source_extension(token: str) -> bool:
    return PurePath(token).suffix.lower() in _SOURCE_EXTENSIONS


def has_cxx_extension(token: str) -> bool:
    return PurePath(token).suffix.lower() in _CXX_SOURCE_EXTENSIONS


def has_object_or_library_extension(token: str) -> bool:
    return PurePath(token).suffix.lower() in _OBJECT_OR_LIBRARY_EXTENSIONS


def gnu_option_expects_value(arg: str) -> bool:
    return arg in _GNU_OPTIONS_WITH_VALUE


def msvc_option_expects_value(arg_lower: str) -> bool:
    return arg_lower in _MSVC_OPTIONS_WITH_VALUE


def looks_like_msvc_switch(arg: str) -> bool:
    if not arg.startswith("/") or len(arg) < 2:
        return False
    if "/" in arg[1:]:
        return False
    lower = arg.lower()
    if lower in _MSVC_STYLE_EXACT:
        return True
    return any(lower.startswith(prefix) for prefix in _MSVC_STYLE_PREFIX)


def args_indicate_cxx(args: Sequence[str]) -> bool:
    i = 0
    while i < len(args):
        token = args[i]
        if token == "-x" and (i + 1) < len(args):
            language = args[i + 1].lower()
            if "c++" in language:
                return True
            if language == "c":
                return False
            i += 2
            continue
        if token.startswith("-x") and len(token) > 2:
            language = token[2:].lower()
            if "c++" in language:
                return True
            if language == "c":
                return False
        if token.startswith("-") or token.startswith("/"):
            i += 1
            continue
        if has_cxx_extension(token):
            return True
        i += 1
    return False


def contains_source_inputs(intent: Intent, args: Sequence[str]) -> bool:
    expect_value_for_previous = False
    expect_source_after_lang_switch = False

    i = 0
    while i < len(args):
        token = args[i]
        if expect_value_for_previous:
            expect_value_for_previous = False
            i += 1
            continue

        if intent == "cl":
            if token.startswith("/"):
                lower = token.lower()
                if lower == "/tc" or lower == "/tp":
                    expect_source_after_lang_switch = True
                    i += 1
                    continue
                if lower.startswith("/tc") or lower.startswith("/tp"):
                    if len(token) > 3:
                        return True
                    expect_source_after_lang_switch = True
                    i += 1
                    continue
                if lower == "/link":
                    break
                if msvc_option_expects_value(lower):
                    expect_value_for_previous = True
                i += 1
                continue
        else:
            if token == "-x":
                if (i + 1) < len(args):
                    lang = args[i + 1].lower()
                    expect_source_after_lang_switch = (
                        lang == "c"
                        or "c++" in lang
                        or lang == "objective-c"
                        or lang == "objective-c++"
                    )
                expect_value_for_previous = True
                i += 1
                continue
            if token.startswith("-x") and len(token) > 2:
                lang = token[2:].lower()
                expect_source_after_lang_switch = (
                    lang == "c" or "c++" in lang or lang == "objective-c" or lang == "objective-c++"
                )
                i += 1
                continue
            if token.startswith("-"):
                if gnu_option_expects_value(token):
                    expect_value_for_previous = True
                i += 1
                continue

        if has_source_extension(token):
            return True
        if expect_source_after_lang_switch and not has_object_or_library_extension(token):
            return True
        expect_source_after_lang_switch = False
        i += 1
    return False


def is_compile_only_mode(intent: Intent, args: Sequence[str]) -> bool:
    if intent == "cl":
        return any(arg.lower() in {"/c", "/e", "/ep"} for arg in args)
    return any(arg in {"-c", "-S", "-E"} for arg in args)


def detect_intent(argv0: str, compiler_binary: Optional[str], args: Sequence[str]) -> Intent:
    for name in (argv0, compiler_binary or ""):
        if not name:
            continue
        detected = intent_from_name(name)
        if detected is not None:
            return detected

    if any(looks_like_msvc_switch(arg) for arg in args):
        return "cl"
    if args_indicate_cxx(args):
        return "g++"
    return "gcc"


def resolve_compiler_binary(intent: Intent, forced_compiler: Optional[str]) -> str:
    if forced_compiler:
        return forced_compiler
    if intent == "cl":
        return non_empty_env("EIPPF_CLANG_CL") or "clang-cl"
    if intent == "g++":
        return non_empty_env("EIPPF_CLANGXX") or "clang++"
    return non_empty_env("EIPPF_CLANG") or "clang"


def parse_invocation(argv: Sequence[str]) -> ParsedInvocation:
    env_pass_plugins: List[str] = []
    plugin_list_env = non_empty_env("EIPPF_PASS_PLUGIN_LIST")
    if plugin_list_env is not None:
        env_pass_plugins.extend(split_plugin_values(plugin_list_env))

    pass_plugin_env = non_empty_env("EIPPF_PASS_PLUGIN")
    if pass_plugin_env is not None:
        env_pass_plugins.extend(split_plugin_values(pass_plugin_env))

    cli_pass_plugins: List[str] = []
    forced_compiler: Optional[str] = None
    raw = list(argv)

    i = 0
    while i < len(raw):
        token = raw[i]
        if token == "--":
            i += 1
            break
        if token == "--pass-plugin":
            if (i + 1) >= len(raw):
                raise ValueError("--pass-plugin requires a value")
            cli_pass_plugins.extend(split_plugin_values(raw[i + 1]))
            i += 2
            continue
        if token.startswith("--pass-plugin="):
            cli_pass_plugins.extend(split_plugin_values(token.split("=", 1)[1]))
            i += 1
            continue
        if token == "--compiler":
            if (i + 1) >= len(raw):
                raise ValueError("--compiler requires a value")
            forced_compiler = raw[i + 1]
            i += 2
            continue
        if token.startswith("--compiler="):
            forced_compiler = token.split("=", 1)[1]
            i += 1
            continue
        break

    compiler_command = raw[i:]
    if not compiler_command:
        raise ValueError("compiler command is empty")

    pass_plugins = cli_pass_plugins if cli_pass_plugins else env_pass_plugins
    pass_plugins = deduplicate_preserve_order(pass_plugins)
    for plugin in pass_plugins:
        if not plugin:
            raise ValueError("pass plugin path cannot be empty")

    strip_mode = (non_empty_env("EIPPF_STRIP_MODE") or "all").lower()
    if strip_mode not in {"all", "debug"}:
        raise ValueError("EIPPF_STRIP_MODE must be 'all' or 'debug'")

    return ParsedInvocation(
        pass_plugins=pass_plugins,
        forced_compiler=forced_compiler,
        compiler_command=compiler_command,
        strip_output=env_bool("EIPPF_STRIP_OUTPUT", False),
        strip_mode=strip_mode,
        strip_tool=non_empty_env("EIPPF_STRIP_TOOL"),
        strip_fail_closed=env_bool("EIPPF_STRIP_FAIL_CLOSED", False),
    )


def split_explicit_compiler(command: Sequence[str]) -> tuple[Optional[str], List[str]]:
    if not command:
        return None, []
    first = command[0]
    if looks_like_known_compiler(first):
        return first, list(command[1:])
    return None, list(command)


def build_forward_command(argv0: str, parsed: ParsedInvocation) -> ForwardCommand:
    explicit_compiler, compiler_args = split_explicit_compiler(parsed.compiler_command)
    intent = detect_intent(argv0, explicit_compiler, compiler_args)
    compiler = resolve_compiler_binary(intent, parsed.forced_compiler)

    mapped_args = list(compiler_args)
    should_inject_pass_plugins = (
        bool(parsed.pass_plugins)
        and not contains_pass_plugin_flag(mapped_args)
        and (is_compile_only_mode(intent, mapped_args) or contains_source_inputs(intent, mapped_args))
    )
    if should_inject_pass_plugins:
        for pass_plugin in parsed.pass_plugins:
            if intent == "cl":
                mapped_args.append(f"/clang:-fpass-plugin={pass_plugin}")
            else:
                mapped_args.append(f"-fpass-plugin={pass_plugin}")

    return ForwardCommand(intent=intent, compiler_args=mapped_args, command=[compiler, *mapped_args])


def detect_output_path(intent: Intent, args: Sequence[str]) -> Optional[str]:
    if intent == "cl":
        i = 0
        while i < len(args):
            token = args[i]
            lower = token.lower()
            if lower == "/link":
                j = i + 1
                while j < len(args):
                    link_arg = args[j]
                    link_lower = link_arg.lower()
                    if link_lower.startswith("/out:") and len(link_arg) > 5:
                        return link_arg[5:]
                    j += 1
                break
            if lower == "/fe":
                if (i + 1) < len(args):
                    return args[i + 1]
            if lower.startswith("/fe") and len(token) > 3:
                return token[3:]
            i += 1
        return None

    i = 0
    while i < len(args):
        token = args[i]
        if token == "-o" and (i + 1) < len(args):
            return args[i + 1]
        if token.startswith("-o") and len(token) > 2:
            return token[2:]
        i += 1

    return "a.exe" if os.name == "nt" else "a.out"


def is_elf_binary(path: str) -> bool:
    try:
        with open(path, "rb") as binary:
            return binary.read(4) == b"\x7fELF"
    except OSError:
        return False


def resolve_strip_tool(requested_tool: Optional[str]) -> Optional[str]:
    if requested_tool is not None:
        requested_basename = basename_lower(requested_tool)
        if requested_basename not in _STRIP_TOOL_WHITELIST:
            raise ValueError("EIPPF_STRIP_TOOL must be llvm-strip or strip")
        resolved = shutil.which(requested_tool)
        if resolved is None and os.path.isabs(requested_tool) and os.access(requested_tool, os.X_OK):
            resolved = requested_tool
        return resolved

    for candidate in ("llvm-strip", "strip"):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return resolved
    return None


def maybe_strip_binary(parsed: ParsedInvocation, forward: ForwardCommand) -> int:
    if not parsed.strip_output:
        return 0
    if is_compile_only_mode(forward.intent, forward.compiler_args):
        return 0

    output_path = detect_output_path(forward.intent, forward.compiler_args)
    if output_path is None or not os.path.exists(output_path):
        if parsed.strip_fail_closed:
            print("eippf_cc.py: strip requested but output artifact is missing", file=sys.stderr)
            return 1
        return 0

    if os.name == "posix" and not is_elf_binary(output_path):
        return 0

    try:
        strip_tool = resolve_strip_tool(parsed.strip_tool)
    except ValueError as exc:
        print(f"eippf_cc.py: {exc}", file=sys.stderr)
        return 1 if parsed.strip_fail_closed else 0

    if strip_tool is None:
        if parsed.strip_fail_closed:
            print("eippf_cc.py: strip tool not found", file=sys.stderr)
            return 1
        return 0

    strip_flag = "--strip-all" if parsed.strip_mode == "all" else "--strip-debug"
    completed = subprocess.run([strip_tool, strip_flag, output_path], check=False)
    if completed.returncode == 0:
        return 0

    if parsed.strip_fail_closed:
        print(
            f"eippf_cc.py: strip failed for '{output_path}' with exit code {completed.returncode}",
            file=sys.stderr,
        )
        return 1
    return 0


def relay_exit_code(returncode: int) -> int:
    if returncode >= 0:
        return returncode
    if os.name == "posix":
        signal_number = -returncode
        try:
            signal.signal(signal_number, signal.SIG_DFL)
            os.kill(os.getpid(), signal_number)
        except OSError:
            return 128 + signal_number
        return 128 + signal_number
    return 1


def main(argv: Sequence[str]) -> int:
    try:
        parsed = parse_invocation(argv)
    except ValueError as exc:
        print(f"eippf_cc.py: {exc}", file=sys.stderr)
        return 2

    forward = build_forward_command(sys.argv[0], parsed)
    try:
        completed = subprocess.run(forward.command, check=False)
    except OSError as exc:
        print(f"eippf_cc.py: failed to execute '{forward.command[0]}': {exc}", file=sys.stderr)
        return 1

    compile_rc = relay_exit_code(completed.returncode)
    if compile_rc != 0:
        return compile_rc

    strip_rc = maybe_strip_binary(parsed, forward)
    if strip_rc != 0:
        return strip_rc
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
