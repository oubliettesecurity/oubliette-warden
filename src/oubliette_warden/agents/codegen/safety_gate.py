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
from typing import Callable

from .base import AttackTechnique, Command, ExecutionEnv


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
    explanation. For now, the stub approves; the gate's overall decision is
    still subject to the deterministic stages above.
    """
    return StageResult("llm_judge", Verdict.APPROVE, "stub: deferred to integration")


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


def evaluate(cmd: Command, env: ExecutionEnv, pipeline: list[StageFn] | None = None) -> GateDecision:
    """Run the full pipeline. DENY short-circuits; ESCALATE accumulates."""
    pipeline = pipeline or DEFAULT_PIPELINE
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
