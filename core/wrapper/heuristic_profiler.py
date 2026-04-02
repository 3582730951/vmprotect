#!/usr/bin/env python3
"""Adaptive compile-time heuristic profiler for SLA/IP-density routing.

Input:
  - LLVM IR text (module .ll) or per-function snippet
Output:
  - route decisions:
      * HOT  -> jit_backend
      * COLD -> interpreter_backend
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List


@dataclass(frozen=True)
class FunctionMetrics:
    name: str
    cyclomatic_complexity: int
    max_loop_depth: int
    instruction_count: int
    math_op_count: int
    call_count: int
    memory_op_count: int


@dataclass(frozen=True)
class RoutingDecision:
    function_name: str
    score: float
    route: str  # "jit_backend" | "interpreter_backend"


class HeuristicProfiler:
    """SLA-aware function router.

    Scoring model (higher means hotter):
      score =
        1.8 * loop_depth +
        1.0 * log2(cyclomatic_complexity + 1) +
        1.2 * math_density +
        0.6 * instruction_pressure -
        0.8 * branch_heaviness
    """

    def __init__(self, hot_threshold: float = 8.5) -> None:
        self.hot_threshold = hot_threshold

    def route(self, metrics: FunctionMetrics) -> RoutingDecision:
        complexity = max(1, metrics.cyclomatic_complexity)
        loop_depth = max(0, metrics.max_loop_depth)
        instr = max(1, metrics.instruction_count)

        math_density = metrics.math_op_count / instr
        instruction_pressure = min(2.0, instr / 120.0)
        branch_heaviness = min(2.0, complexity / 25.0)

        # Lightweight approximation for log2(complexity+1)
        log2_complexity = (complexity + 1).bit_length() - 1

        score = (
            1.8 * loop_depth
            + 1.0 * float(log2_complexity)
            + 1.2 * math_density * 10.0
            + 0.6 * instruction_pressure
            - 0.8 * branch_heaviness
        )

        route = "jit_backend" if score >= self.hot_threshold else "interpreter_backend"
        return RoutingDecision(function_name=metrics.name, score=score, route=route)

    def route_module(self, metrics_list: Iterable[FunctionMetrics]) -> List[RoutingDecision]:
        return [self.route(metrics) for metrics in metrics_list]


def _estimate_loop_depth(ir_lines: List[str]) -> int:
    # Conservative approximation:
    # count distinct backedge-like branches: `br ... label %Lx` to seen labels.
    labels_seen: Dict[str, int] = {}
    depth = 0
    for idx, line in enumerate(ir_lines):
        line = line.strip()
        if line.endswith(":"):
            labels_seen[line[:-1]] = idx
            continue
        if " br " not in f" {line} ":
            continue
        for target in re.findall(r"label\s+%([A-Za-z0-9_.]+)", line):
            if target in labels_seen and labels_seen[target] < idx:
                depth += 1
    return min(depth, 8)


def extract_metrics_from_llvm_ir(function_name: str, function_ir: str) -> FunctionMetrics:
    lines = [line for line in function_ir.splitlines() if line.strip()]
    inst_count = 0
    cond_branch_count = 0
    switch_case_count = 0
    math_ops = 0
    call_ops = 0
    mem_ops = 0

    math_re = re.compile(r"\b(f?add|f?sub|f?mul|f?div|fma|and|or|xor|shl|lshr|ashr)\b")
    mem_re = re.compile(r"\b(load|store|getelementptr|memcpy|memmove|memset)\b")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(";"):
            continue
        if stripped.endswith(":"):
            continue

        inst_count += 1
        if re.search(r"\bbr\s+i1\b", stripped):
            cond_branch_count += 1
        if stripped.startswith("switch "):
            # Number of case labels in switch body line.
            switch_case_count += stripped.count("label %")
        if math_re.search(stripped):
            math_ops += 1
        if re.search(r"\bcall\b|\binvoke\b", stripped):
            call_ops += 1
        if mem_re.search(stripped):
            mem_ops += 1

    cyclomatic = 1 + cond_branch_count + max(0, switch_case_count - 1)
    loop_depth = _estimate_loop_depth(lines)

    return FunctionMetrics(
        name=function_name,
        cyclomatic_complexity=cyclomatic,
        max_loop_depth=loop_depth,
        instruction_count=inst_count,
        math_op_count=math_ops,
        call_count=call_ops,
        memory_op_count=mem_ops,
    )
