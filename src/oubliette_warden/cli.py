"""``oubliette-warden`` — the operator CLI.

The console script used to be the screencast runner: one positional intent
string that printed four demo shots. That is a fine demo and a non-existent
product surface. An operator needs to produce a plan, keep it, look at what the
safety pipeline would decide about it, and only then run anything.

Commands:

* ``plan``  — intent in, task graph out, persisted as JSON so it can be
  reviewed, edited, and diffed. Tasks are emitted **unapproved**.
* ``gate``  — evaluate a saved plan through the full safety pipeline and report
  per-task verdicts. **Executes nothing, ever.**
* ``serve`` — the review/audit API.
* ``demo``  — the original screencast narrative, preserved.

There is deliberately no ``run`` command yet. Real execution needs a decision
about which adapters may run in which environment, and inventing that policy
here — rather than agreeing it — is exactly how a safety-gated framework grows
an ungated path.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from pathlib import Path
from typing import IO, Any

from .agents.codegen.base import CommandAdapter, ExecutionEnv, Task
from .agents.codegen.msf_adapter import MSFAuxAdapter
from .agents.codegen.nmap_adapter import NmapAdapter
from .agents.codegen.safety_gate import GateContext, Verdict, evaluate
from .agents.planner.planner import Edge, Planner, TaskGraph


class CLIError(Exception):
    """Something the operator can fix, reported without a traceback."""


#: Planner phase -> the adapter that turns its tasks into commands.
#:
#: The planner emits these four phases; ``research`` produces no command. An
#: unknown phase raises rather than resolving to None, because "no adapter" and
#: "nothing to do" look identical in a report and only one of them is safe.
PHASE_ADAPTERS: dict[str, str] = {
    "recon": "nmap",
    "service_version": "nmap",
    "vuln_enum": "msf-aux",
    "research": "",  # no executable command
}

AdapterFor = Callable[[Task], "CommandAdapter | None"]


def default_adapter_for(task: Task) -> CommandAdapter | None:
    """Resolve a task to the adapter that would build its command.

    Adapters are constructed without live clients: this path only ever calls
    ``adapter.plan()``, which is pure. Nothing here can execute.
    """
    phase = str(task.metadata.get("phase", ""))
    if phase not in PHASE_ADAPTERS:
        raise CLIError(
            f"no adapter registered for planner phase {phase!r}. "
            f"Known phases: {', '.join(sorted(k for k in PHASE_ADAPTERS if k))}"
        )
    name = PHASE_ADAPTERS[phase]
    if not name:
        return None
    return NmapAdapter() if name == "nmap" else MSFAuxAdapter()


# --- serialisation ----------------------------------------------------------


def plan_to_dict(graph: TaskGraph) -> dict[str, Any]:
    return {
        "schema": "oubliette.warden.plan/1",
        "intent": graph.intent,
        "target_scope": list(graph.target_scope),
        "nodes": [
            {
                "task_id": t.task_id,
                "intent": t.intent,
                "target_scope": list(t.target_scope),
                "attck_technique_ids": list(t.attck_technique_ids),
                "operator_approved": bool(t.operator_approved),
                "metadata": dict(t.metadata),
            }
            for t in graph.nodes
        ],
        "edges": [{"before": e.before, "after": e.after} for e in graph.edges],
    }


def plan_from_dict(data: dict[str, Any]) -> TaskGraph:
    try:
        nodes = [
            Task(
                task_id=n["task_id"],
                intent=n["intent"],
                target_scope=list(n["target_scope"]),
                attck_technique_ids=list(n.get("attck_technique_ids", [])),
                operator_approved=bool(n.get("operator_approved", False)),
                metadata=dict(n.get("metadata", {})),
            )
            for n in data["nodes"]
        ]
        edges = [Edge(before=e["before"], after=e["after"]) for e in data.get("edges", [])]
        return TaskGraph(
            intent=data["intent"],
            target_scope=list(data["target_scope"]),
            nodes=nodes,
            edges=edges,
        )
    except (KeyError, TypeError) as exc:
        raise CLIError(f"plan file is missing required fields: {exc}") from exc


def load_plan(path: Path) -> TaskGraph:
    if not path.is_file():
        raise CLIError(f"plan file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise CLIError(f"{path}: not valid JSON ({exc})") from exc
    return plan_from_dict(data)


# --- commands ---------------------------------------------------------------


def cmd_version(args: argparse.Namespace, out: IO[str], err: IO[str]) -> int:
    try:
        v = _dist_version("oubliette-warden")
    except PackageNotFoundError:  # pragma: no cover - source checkout
        v = "unknown (not installed)"
    print(f"oubliette-warden {v} — safety-gated agent framework", file=out)
    return 0


def cmd_plan(args: argparse.Namespace, out: IO[str], err: IO[str]) -> int:
    planner = Planner()
    try:
        graph = planner.plan(args.intent, explicit_scope=args.scope or None)
    except ValueError as exc:
        # The planner refuses an intent with no target scope. That refusal is
        # correct -- an unscoped plan is an unbounded one -- so surface it as an
        # error the operator can act on rather than a traceback.
        print(f"error: {exc}", file=err)
        return 2

    payload = json.dumps(plan_to_dict(graph), indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")
        print(f"Wrote {path}: {len(graph.nodes)} tasks, {len(graph.edges)} edges", file=out)
        print("\nTasks are UNAPPROVED. Review them, then:", file=out)
        print(f"    oubliette-warden gate --plan {path}", file=out)
    else:
        print(payload, file=out)
    return 0


def _gate_plan(
    graph: TaskGraph,
    env: ExecutionEnv,
    adapter_for: AdapterFor,
) -> list[dict[str, Any]]:
    """Evaluate every task. Builds commands; never executes them.

    ``completed_task_ids`` advances only for tasks that would have been
    approved, mirroring a real run: a blocked task must not satisfy a
    successor's ordering check, or the report would claim a plan runs when it
    would in fact stall at the first denial.
    """
    completed: set[str] = set()
    rows: list[dict[str, Any]] = []
    for task in graph.topological_order():
        adapter = adapter_for(task)
        if adapter is None:
            rows.append({
                "task_id": task.task_id,
                "phase": task.metadata.get("phase"),
                "adapter": None,
                "command": None,
                "verdict": None,
                "reasons": [],
                "note": "no executable command for this node",
            })
            completed.add(task.task_id)
            continue
        command = adapter.plan(task)
        decision = evaluate(
            command,
            env,
            context=GateContext(plan=graph, completed_task_ids=set(completed)),
        )
        if decision.final == Verdict.APPROVE:
            completed.add(task.task_id)
        rows.append({
            "task_id": task.task_id,
            "phase": task.metadata.get("phase"),
            "adapter": adapter.name,
            "command": " ".join(command.argv),
            "verdict": decision.final.value.upper(),
            "reasons": list(decision.reasons()),
            "stages": [
                {"stage": s.stage, "verdict": s.verdict.value.upper(), "reason": s.reason}
                for s in decision.stages
            ],
        })
    return rows


def cmd_gate(args: argparse.Namespace, out: IO[str], err: IO[str]) -> int:
    graph = load_plan(Path(args.plan))

    if args.approve_all or args.approve:
        approve = set(args.approve or [])
        graph = TaskGraph(
            intent=graph.intent,
            target_scope=graph.target_scope,
            nodes=[
                Task(
                    task_id=t.task_id,
                    intent=t.intent,
                    target_scope=t.target_scope,
                    attck_technique_ids=t.attck_technique_ids,
                    operator_approved=(args.approve_all or t.task_id in approve),
                    metadata=t.metadata,
                )
                for t in graph.nodes
            ],
            edges=graph.edges,
        )

    env = ExecutionEnv(args.env)
    rows = _gate_plan(graph, env, args.adapter_for or default_adapter_for)
    blocked = [r for r in rows if r["verdict"] not in (None, "APPROVE")]

    if args.format == "json":
        print(json.dumps({
            "schema": "oubliette.warden.gate-report/1",
            "intent": graph.intent,
            "env": env.value,
            "approved_locally": bool(args.approve_all or args.approve),
            "tasks": rows,
        }, indent=2), file=out)
    else:
        print(f"\nplan: {graph.intent}", file=out)
        print(f"env:  {env.value}", file=out)
        if args.approve_all or args.approve:
            # Say this plainly: a flag on this machine is not an approval record.
            print(
                "\nNOTE: approvals below are LOCAL what-if only. They are not "
                "operator approvals from the review queue and grant nothing.",
                file=out,
            )
        print("-" * 68, file=out)
        for row in rows:
            if row["verdict"] is None:
                print(f"  {row['task_id']:<16} {'(no command)':<10} {row['note']}", file=out)
                continue
            print(f"  {row['task_id']:<16} {row['verdict']:<10} {row['command']}", file=out)
            for reason in row["reasons"]:
                print(f"  {'':<16} {'':<10} - {reason}", file=out)
        print("-" * 68, file=out)
        # Count only executable nodes. Folding the no-command nodes into
        # "would proceed" inflates the number an operator reads as "how much of
        # my plan is cleared to run".
        executable = [r for r in rows if r["verdict"] is not None]
        no_command = len(rows) - len(executable)
        print(
            f"{len(executable) - len(blocked)} of {len(executable)} executable "
            f"task(s) would proceed; {len(blocked)} blocked"
            + (f"; {no_command} node(s) have no command." if no_command else "."),
            file=out,
        )
        print("Nothing was executed.", file=out)

    # Non-zero when the plan would not run, so scripts and CI can branch on it.
    return 1 if blocked else 0


def cmd_serve(args: argparse.Namespace, out: IO[str], err: IO[str]) -> int:
    from .demo import ui

    return ui.main([str(args.port)])


def cmd_demo(args: argparse.Namespace, out: IO[str], err: IO[str]) -> int:
    from .demo import run as demo_run

    return demo_run.main([args.intent] if args.intent else [])


# --- parser -----------------------------------------------------------------


def _force_utf8_streams() -> None:
    """Let gate reasons print on a stock Windows console.

    Safety-gate reasons contain an em-dash ("llm_judge not implemented — failing
    closed"). On cp1252 that renders as a replacement character, which in a
    *safety* report is worse than cosmetic: the operator is reading why a
    command was blocked, and mojibake there invites them to distrust the output.
    Only applied when we own the real streams, never to injected ones.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - exotic streams
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oubliette-warden",
        description="Safety-gated agent framework: plan, gate, then act.",
        epilog=(
            "Typical use:\n"
            "  oubliette-warden plan --intent 'enumerate hosts on 10.50.0.0/24' -o plan.json\n"
            "  oubliette-warden gate --plan plan.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    p_version = sub.add_parser("version", help="show the installed version")
    p_version.set_defaults(func=cmd_version)

    p_plan = sub.add_parser("plan", help="turn an intent into a reviewable task graph")
    p_plan.add_argument("--intent", required=True, help="what you want done")
    p_plan.add_argument(
        "--scope", action="append",
        help="explicit target scope (repeatable); overrides extraction from the intent",
    )
    p_plan.add_argument("-o", "--output", help="write JSON here instead of stdout")
    p_plan.set_defaults(func=cmd_plan)

    p_gate = sub.add_parser(
        "gate", help="evaluate a saved plan through the safety pipeline (executes nothing)"
    )
    p_gate.add_argument("--plan", required=True, help="a plan written by `warden plan`")
    p_gate.add_argument(
        "--env", default=ExecutionEnv.CALDERA_ONLY.value,
        choices=[e.value for e in ExecutionEnv],
        help="execution substrate to evaluate against (default: caldera_only)",
    )
    p_gate.add_argument(
        "--approve", action="append",
        help="LOCAL what-if: treat this task id as operator-approved (repeatable)",
    )
    p_gate.add_argument(
        "--approve-all", action="store_true",
        help="LOCAL what-if: treat every task as operator-approved",
    )
    p_gate.add_argument("-f", "--format", choices=("text", "json"), default="text")
    p_gate.set_defaults(func=cmd_gate)

    p_serve = sub.add_parser("serve", help="run the review/audit API")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=cmd_serve)

    p_demo = sub.add_parser("demo", help="the original screencast narrative")
    p_demo.add_argument("intent", nargs="?", default=None)
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(
    argv: Sequence[str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    adapter_for: AdapterFor | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if stdout is None and stderr is None:
        _force_utf8_streams()
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    if not getattr(args, "command", None):
        parser.print_help(out)
        return 0

    args.adapter_for = adapter_for
    try:
        return int(args.func(args, out, err))
    except CLIError as exc:
        print(f"error: {exc}", file=err)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
