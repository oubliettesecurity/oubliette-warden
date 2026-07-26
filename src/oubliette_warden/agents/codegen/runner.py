"""Execution session — the thin runner that drives a plan to execution.

This closes the CRIT-1 gap. CRIT-1 wired the plan_consistency stage into the
safety gate and made it fail closed when no plan context is present, but nothing
in the real command-execution path ever *set* an adapter's ``_gate_context``.
The adapters gate from their own ``execute()`` (via
``CommandAdapter._gate_or_raise``), which reads ``self._gate_context`` — so
without a component that owns the plan and threads that context in, every real
``execute()`` would DENY as unattributable. No higher multi-adapter orchestrator
existed; only ``demo/gate.py`` built a ``GateContext`` and handed it straight to
``evaluate()``, bypassing the adapter path entirely.

``ExecutionSession`` is that missing driver, kept deliberately thin:

  - it owns the authoritative ``TaskGraph`` and the set of completed task ids;
  - for each task in topological order it selects an adapter, sets that adapter's
    ``_gate_context = GateContext(plan, completed_task_ids)`` (the command's
    ``task_id`` is already stamped by ``adapter.plan(task)``), and runs the
    adapter's real ``execute()`` so plan_consistency verifies attributability,
    operator-approval (anchored) and ordering at execution time;
  - it advances ``completed_task_ids`` only when a task actually finishes, so a
    blocked (DENY/ESCALATE) task cannot satisfy a successor's ordering check;
  - it resets ``_gate_context`` back to ``None`` after each task, restoring the
    fail-closed default so an adapter reused outside a session cannot execute
    unattributed.

The session does not re-implement the gate; the adapter's ``execute()`` remains
the sole decision point. The session only supplies the context the gate needs
and records the resulting :class:`~oubliette_warden.agents.codegen.safety_gate.GateDecision`
per task for the audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from .base import Command, CommandAdapter, ExecutionEnv, Finding, Task
from .safety_gate import GateContext, GateDecision

if TYPE_CHECKING:
    from ..planner.planner import TaskGraph

# Resolver: given a task, return the adapter that should run it, or None for a
# node that produces no executable command (e.g. a research handoff).
AdapterFor = Callable[[Task], "CommandAdapter | None"]


@dataclass
class TaskOutcome:
    """Per-task result of a session run, for audit/replay."""

    task_id: str
    status: str  # "executed" | "blocked" | "skipped"
    decision: GateDecision | None = None
    finding: Finding | None = None
    command: Command | None = None
    error: Exception | None = None


@dataclass
class ExecutionSession:
    """Drives a plan's tasks through their adapters, threading gate context.

    ``adapter_for`` maps a task to the adapter that executes it (or ``None`` to
    skip a no-command node). ``env`` is the execution substrate (Phase I:
    ``CALDERA_ONLY``).
    """

    plan: "TaskGraph"
    env: ExecutionEnv
    adapter_for: AdapterFor
    completed_task_ids: set[str] = field(default_factory=set)
    outcomes: list[TaskOutcome] = field(default_factory=list)

    def run(self) -> list[TaskOutcome]:
        """Execute every task in topological order. Returns the per-task outcomes.

        A DENY or ESCALATE raises out of ``adapter.execute()`` and is captured as
        a ``blocked`` outcome; that task is not added to ``completed_task_ids``,
        so any successor depending on it is DENIED as skip-ahead on this same run.
        """
        for task in self.plan.topological_order():
            if task.task_id in self.completed_task_ids:
                continue  # idempotent across repeated run() calls
            adapter = self.adapter_for(task)
            if adapter is None:
                # No executable command for this node (e.g. research handoff);
                # it still "completes" so downstream ordering holds.
                self.completed_task_ids.add(task.task_id)
                self.outcomes.append(TaskOutcome(task.task_id, "skipped"))
                continue
            self.outcomes.append(self._run_task(task, adapter))
        return self.outcomes

    def _run_task(self, task: Task, adapter: CommandAdapter) -> TaskOutcome:
        command = adapter.plan(task)  # stamps command.task_id from task.task_id
        # Thread the plan context so the gate's plan_consistency stage can
        # attribute + order-check + approval-check this command at execution time.
        adapter._gate_context = GateContext(
            plan=self.plan,
            completed_task_ids=set(self.completed_task_ids),
        )
        try:
            finding = adapter.execute(command, self.env)
        except Exception as exc:  # DENY/ESCALATE surface as adapter errors
            return TaskOutcome(
                task.task_id,
                "blocked",
                decision=self._decision_of(adapter),
                command=command,
                error=exc,
            )
        else:
            self.completed_task_ids.add(task.task_id)
            return TaskOutcome(
                task.task_id,
                "executed",
                decision=self._decision_of(adapter),
                finding=finding,
                command=command,
            )
        finally:
            # Restore fail-closed default: an adapter must not carry stale plan
            # context into any later use outside this session.
            adapter._gate_context = None

    @staticmethod
    def _decision_of(adapter: CommandAdapter) -> Any:
        return getattr(adapter, "_last_gate_decision", None)
