"""Shot 4 of the screencast — five-stage safety pipeline gates a command.

Usage:
    python -m oubliette_warden.demo.gate [INTENT]
"""

from __future__ import annotations

import sys

from ..agents.codegen.base import ExecutionEnv
from ..agents.codegen.nmap_adapter import NmapAdapter
from ..agents.codegen.safety_gate import GateContext, evaluate
from ..agents.planner.planner import Planner


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    intent = args[0] if args else "enumerate hosts on 10.50.0.0/24"

    planner = Planner()
    graph = planner.plan(intent)
    nmap = NmapAdapter()

    first_task = next(
        t for t in graph.topological_order()
        if t.metadata.get("phase") != "research"
    )
    cmd = nmap.plan(first_task)

    # CRIT-1: the gate now runs plan_consistency FIRST and fails closed without
    # plan attribution, so the orchestrator must supply the plan/completed-set
    # context. Here the first task has no completed predecessors.
    context = GateContext(plan=graph, completed_task_ids=set())

    print(f"command: {' '.join(cmd.argv)}")
    print(f"env:     CALDERA_ONLY")
    print("-" * 60)
    print("safety pipeline verdicts:")
    decision = evaluate(cmd, ExecutionEnv.CALDERA_ONLY, context=context)
    for stage in decision.stages:
        print(f"  {stage.stage:<18} {stage.verdict.value.upper():<10} {stage.reason}")
    print("-" * 60)
    print(f"final = {decision.final.value.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
