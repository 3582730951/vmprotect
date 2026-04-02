# Repository Guidelines

## Project Structure & Module Organization
This project is constrained by `plan.txt` and follows a plan-first workflow. Use these boundaries:
- Implement production code only under `core/`.
- Store architecture/planning outputs under `plan/` using date names (example: `plan/2026-2-26.txt`).
- Keep repository root limited to governance docs (for example `AGENTS.md`, `plan.txt`).

Target module layout:
- `core/wrapper/`: compiler proxy (`cl.exe` / `gcc/g++` interception and flag mapping to Clang).
- `core/passes/`: LLVM IR passes (string extraction/encryption, CFF/BCF).
- `core/runtime/`: dynamic import resolver, attestation checks, hybrid JIT runtime.
- `core/include/`: shared APIs and contracts.
- `core/tests/`: unit/integration/perf tests mirroring module paths.

## Build, Test, and Development Commands
Standardize on CMake + CTest for all new components:
- `cmake -S core -B build -G Ninja`: configure.
- `cmake --build build -j`: build all targets.
- `ctest --test-dir build --output-on-failure`: run tests.
- `cmake --build build --target perf_smoke`: run overhead sanity checks (<10% target).

## Coding Style & Naming Conventions
Target language is modern C++20.
- Indentation: 4 spaces; no tabs.
- Filenames: `snake_case.cpp` / `snake_case.hpp`; tests end with `_test.cpp`.
- Types/classes: `PascalCase`; functions/variables: `snake_case`; constants: `kPascalCase`.
- Keep functions single-purpose and under 50 logical lines when possible.
- Do not use exceptions/RTTI in protected modules; use `Result<T, ErrorCode>`.
- No ownership via raw pointers; use `std::unique_ptr` with secure deleters where needed.

## Testing Guidelines
Mirror source layout in `core/tests/` (example: `core/runtime/resolver/*` -> `core/tests/runtime/resolver/*`).
For each new public API, add:
- 1 success-path test,
- 1 failure-path test,
- 1 edge/security-path test.

For performance-sensitive changes, include before/after latency or throughput notes and keep end-to-end overhead below 10%.

## Commit & Pull Request Guidelines
Use Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.
- Scope one concern per commit.
- PRs must include: objective, impacted modules, exact test commands/results, and security/performance impact.
- Link issue IDs and include logs/screenshots only when they add debugging value.

## Delivery Rules
- Use Chinese for planning deliverables when requested by active project instructions.
- For architecture milestones, deliver in explicit phases (Phase 1, Phase 2, ...), not ad-hoc notes.

## Multi-Agent Contract
- Collaboration model for this repository is fixed to 3 roles: `Agent 1 (Planner)`, `Agent 2 (Engineer)`, `Agent 3 (Security Reviewer)`.
- All implementation sequencing follows `plan/2026-2-26.txt` unless an explicit superseding plan file is approved.
- `Planner` defines phase scope and acceptance criteria, `Engineer` implements, `Reviewer` audits with priority on security regressions and performance budget (<10% overhead).
- In this local workspace, role execution is represented explicitly in output sections for traceability.
