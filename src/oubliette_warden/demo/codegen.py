"""Shot 3 of the screencast — CodeGen agent emits an Nmap command.

Usage:
    python -m oubliette_warden.demo.codegen [INTENT] [TARGET]
"""

from __future__ import annotations

import sys

from ..agents.codegen.nmap_adapter import NmapAdapter
from ..agents.planner.planner import Planner


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    intent = args[0] if args else "enumerate hosts on 10.50.0.0/24"

    planner = Planner()
    graph = planner.plan(intent)
    nmap = NmapAdapter()

    print(f"intent: {intent}")
    print("-" * 60)
    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            continue  # research handoff has no CodeGen output
        cmd = nmap.plan(task)
        print(f"task {task.task_id}:")
        print(f"  argv:         {' '.join(cmd.argv)}")
        print(f"  ATT&CK ids:   {', '.join(cmd.attck_technique_ids)}")
        print(f"  active probe: {cmd.is_active_probe}")
        print(f"  policy:       CALDERA-only (Phase I)")
        print(f"  rationale:    {cmd.rationale}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
