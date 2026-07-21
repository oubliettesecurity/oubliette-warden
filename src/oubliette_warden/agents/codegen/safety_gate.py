"""
Pre-execution safety gate for the Oubliette Warden Code Generation & Execution agent.

Wraps Oubliette Shield's five-stage pipeline as a gate that decides whether a
proposed Command may execute. Phase I implements a deterministic skeleton with
typed checks; the LLM-judge and rag_guard stages are wired through stubs that
can be swapped for the real `oubliette_shield` modules at integration time.

Decisions are one of:
    APPROVE — execute as proposed
    DENY    — refuse; record reason; surface to operator
    ESCALATE — execute only after explicit operator approval

Every decision is recorded with all five stages' verdicts, so any later audit
can reconstruct exactly why a command was allowed or blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

from .base import AttackTechnique, Command, ExecutionEnv

if TYPE_CHECKING:  # avoid an import cycle; duck-type the graph at runtime
    from ..planner.planner import TaskGraph


class Verdict(str, Enum):
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class StageResult:
    stage: str
    verdict: Verdict
    reason: str


@dataclass(frozen=True)
class GateDecision:
    final: Verdict
    stages: list[StageResult] = field(default_factory=list)

    def reasons(self) -> list[str]:
        return [s.reason for s in self.stages]


# Stage signature: takes (command, env), returns StageResult.
StageFn = Callable[[Command, ExecutionEnv], StageResult]


@dataclass(frozen=True)
class GateContext:
    """Plan/execution context threaded to the gate for the current run.

    Carried by the orchestrator that owns the plan (parallel to an adapter's
    optional ``_review_queue``). ``plan`` is the authoritative TaskGraph and
    ``completed_task_ids`` is the set of task ids finished so far, so the
    plan_consistency stage can verify attributability and correct ordering.
    """

    plan: "TaskGraph"
    completed_task_ids: set[str] = field(default_factory=set)


def _stage_pre_filter(cmd: Command, env: ExecutionEnv) -> StageResult:
    """Cheapest deterministic checks. Reject obvious violations early."""
    if not cmd.argv:
        return StageResult("pre_filter", Verdict.DENY, "empty argv")
    if not cmd.target_scope:
        return StageResult("pre_filter", Verdict.DENY, "no target scope declared")
    if env != ExecutionEnv.CALDERA_ONLY:
        return StageResult(
            "pre_filter",
            Verdict.DENY,
            f"Phase I builds enforce CALDERA_ONLY; got {env.value}",
        )
    if cmd.is_impact_class():
        return StageResult("pre_filter", Verdict.DENY, "Impact-tactic commands forbidden in Phase I")
    return StageResult("pre_filter", Verdict.APPROVE, "ok")


def _stage_pattern_detector(cmd: Command, env: ExecutionEnv) -> StageResult:
    """Pattern-based recognition of dangerous flags / argument shapes."""
    forbidden_substrings = ("rm -rf", "dd if=", "mkfs", ":(){", "shutdown", "reboot")
    joined = " ".join(cmd.argv).lower()
    for needle in forbidden_substrings:
        if needle in joined:
            return StageResult(
                "pattern_detector",
                Verdict.DENY,
                f"forbidden token detected: {needle!r}",
            )
    if any(arg.startswith("$(") or arg.startswith("`") for arg in cmd.argv):
        return StageResult(
            "pattern_detector",
            Verdict.DENY,
            "shell-substitution token in argv",
        )
    return StageResult("pattern_detector", Verdict.APPROVE, "ok")


def _stage_rag_guard(cmd: Command, env: ExecutionEnv) -> StageResult:
    """Stub for retrieval-grounded policy check.

    Phase I returns APPROVE for adapters on a known-good list. The real
    implementation will call `oubliette_shield.rag_guard` against a curated
    policy corpus.
    """
    known_good_adapters = {"nmap", "msf-aux"}
    if cmd.adapter_name not in known_good_adapters:
        return StageResult(
            "rag_guard",
            Verdict.ESCALATE,
            f"adapter {cmd.adapter_name!r} not on Phase I known-good list",
        )
    return StageResult("rag_guard", Verdict.APPROVE, "ok")


def _stage_llm_judge(cmd: Command, env: ExecutionEnv) -> StageResult:
    """Stub for LLM adjudication.

    Phase I integration point: when wired to a real judge, this stage receives
    the full command + planning rationale and returns a verdict with a free-form
    explanation. No real judge is wired in yet, so this is a fail-closed
    stopgap: it ESCALATEs every command to operator review rather than
    silently APPROVEing work no judge has actually looked at.
    """
    return StageResult(
        "llm_judge",
        Verdict.ESCALATE,
        "llm_judge not implemented — failing closed",
    )


def _stage_mcp_guard(cmd: Command, env: ExecutionEnv) -> StageResult:
    """Final boundary check before the command leaves the agent."""
    if AttackTechnique.IMPACT in cmd.attck_tactics:
        return StageResult("mcp_guard", Verdict.DENY, "Impact tactic — final-stage block")
    if cmd.expected_runtime_seconds > 1800:
        return StageResult(
            "mcp_guard",
            Verdict.ESCALATE,
            f"runtime estimate {cmd.expected_runtime_seconds}s exceeds Phase I cap",
        )
    return StageResult("mcp_guard", Verdict.APPROVE, "ok")


DEFAULT_PIPELINE: list[StageFn] = [
    _stage_pre_filter,
    _stage_pattern_detector,
    _stage_rag_guard,
    _stage_llm_judge,
    _stage_mcp_guard,
]


def _make_attribution_stage(cmd: Command, context: "GateContext | None") -> StageFn:
    """Build the plan_consistency stage for the runtime default pipeline.

    Fail-closed (CRIT-1 §3d): when there is no plan context, or the command
    carries no task_id, the command is unattributable and the stage DENYs —
    no command executes without plan attribution. Otherwise it delegates to the
    real plan_consistency verifier, closed over the plan and completed-task set.
    """
    if context is None or not cmd.task_id:
        def _deny_unattributable(_cmd: Command, _env: ExecutionEnv) -> StageResult:
            return StageResult(
                "plan_consistency",
                Verdict.DENY,
                "unattributable: no plan context",
            )

        return _deny_unattributable

    # Local import avoids a safety_gate<->plan_consistency import cycle.
    from .plan_consistency import make_plan_consistency_stage

    return make_plan_consistency_stage(
        context.plan, cmd.task_id, context.completed_task_ids
    )


def evaluate(
    cmd: Command,
    env: ExecutionEnv,
    pipeline: list[StageFn] | None = None,
    *,
    context: "GateContext | None" = None,
) -> GateDecision:
    """Run the full pipeline. DENY short-circuits; ESCALATE accumulates.

    On the default pipeline (``pipeline is None``), plan_consistency runs FIRST:
    attributability gates before any other check, and fails closed when plan
    context is absent (see ``_make_attribution_stage``). Passing an explicit
    ``pipeline`` runs exactly those stages (used by unit tests that target the
    downstream stages, and by callers that compose their own pipeline).
    """
    if pipeline is None:
        pipeline = [_make_attribution_stage(cmd, context), *DEFAULT_PIPELINE]
    results: list[StageResult] = []
    final = Verdict.APPROVE
    for stage in pipeline:
        r = stage(cmd, env)
        results.append(r)
        if r.verdict == Verdict.DENY:
            return GateDecision(final=Verdict.DENY, stages=results)
        if r.verdict == Verdict.ESCALATE:
            final = Verdict.ESCALATE
    return GateDecision(final=final, stages=results)
