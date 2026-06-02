"""Shot 2 of the screencast — planner emits an ATT&CK-aligned task graph.

Usage:
    python -m oubliette_warden.demo.plan "enumerate hosts on 10.50.0.0/24"
"""

from __future__ import annotations

import sys

from ..agents.planner.planner import Planner


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m oubliette_warden.demo.plan <intent>", file=sys.stderr)
        return 2
    intent = " ".join(args)

    planner = Planner()
    graph = planner.plan(intent)

    print(f"intent: {intent}")
    print(f"scope:  {', '.join(graph.target_scope)}")
    print("-" * 60)
    for i, task in enumerate(graph.topological_order(), start=1):
        attck = ", ".join(task.attck_technique_ids) or "—"
        print(f"  {i}. {task.task_id}  phase={task.metadata.get('phase', '?'):<14}  ATT&CK=[{attck}]")
    print("-" * 60)
    print(f"{len(graph.nodes)} task(s) emitted, {len(graph.edges)} dependency edge(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
