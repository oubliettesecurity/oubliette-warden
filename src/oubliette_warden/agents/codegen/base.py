"""
Command-adapter base for the Oubliette Warden Code Generation & Execution agent.

Tools that the CodeGen agent can emit (Nmap, MSF auxiliary modules, etc.) implement
this protocol. Adapters are responsible for:

  1. Generating a parameterized command from a structured Task record
  2. Declaring the command's safety attributes so the safety pipeline can gate it
  3. Executing the command in the configured emulation substrate (CALDERA-only
     in Phase I — enforced by policy, not by adapter politeness)
  4. Parsing the tool's output into a normalized Finding record

The adapter does NOT decide whether to run a command. That is the safety
pipeline's job. Adapters surface metadata; gates make decisions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionEnv(str, Enum):
    """Where a command is allowed to execute. Phase I is CALDERA_ONLY."""

    CALDERA_ONLY = "caldera_only"
    LAB_RANGE = "lab_range"  # Phase II only
    LIVE = "live"  # Phase III only, never reachable in Phase I builds


class AttackTechnique(str, Enum):
    """Coarse ATT&CK tactic bucket — adapters declare what they enable."""

    RECONNAISSANCE = "TA0043"
    DISCOVERY = "TA0007"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass(frozen=True)
class Task:
    """A single planning-graph node handed to the CodeGen agent."""

    task_id: str
    intent: str
    target_scope: list[str]
    attck_technique_ids: list[str] = field(default_factory=list)
    operator_approved: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Command:
    """A concrete shell-class command emitted by an adapter, pre-gate."""

    adapter_name: str
    argv: list[str]
    target_scope: list[str]
    attck_tactics: list[AttackTechnique]
    attck_technique_ids: list[str]
    is_active_probe: bool
    expected_runtime_seconds: int
    rationale: str
    # Links this command back to the planned Task that produced it. Populated by
    # each adapter's plan(task) from task.task_id. An empty task_id is treated as
    # unattributable by the safety gate's plan_consistency stage (fail-closed).
    task_id: str = ""

    def is_impact_class(self) -> bool:
        return AttackTechnique.IMPACT in self.attck_tactics


@dataclass(frozen=True)
class Finding:
    """Normalized output from an adapter, post-execution."""

    adapter_name: str
    task_id: str
    summary: str
    raw_output_path: str | None
    parsed: dict[str, Any]
    attck_technique_ids: list[str] = field(default_factory=list)
    candidate_cves: list[str] = field(default_factory=list)


class CommandAdapter(ABC):
    """Base class for any tool the CodeGen agent can emit and execute."""

    name: str = ""
    version: str = "0.0.0"

    # Optional operator review queue. When set, ESCALATE verdicts from the
    # safety gate are routed here and block execution until an operator records
    # an APPROVE for the specific command. Adapters set this in __init__.
    _review_queue: Any = None

    # Optional plan/execution context for the run. When set by the orchestrator
    # that owns the plan, it carries the TaskGraph and the set of completed
    # task ids so the safety gate's plan_consistency stage can verify that this
    # command is attributable to a real, correctly-ordered planned task. When
    # unset (None), plan_consistency fails closed: no command executes without
    # plan attribution. Typed as Any to avoid a base<->safety_gate import cycle;
    # it holds a ``safety_gate.GateContext``.
    _gate_context: Any = None

    # Last GateDecision produced by ``_gate_or_raise``. Populated on every gate
    # run — including the DENY/ESCALATE paths that raise — so a driving runner
    # (ExecutionSession) can record *why* a command was admitted or blocked for
    # the audit trail without re-evaluating the gate. Typed as Any to avoid a
    # base<->safety_gate import cycle; it holds a ``safety_gate.GateDecision``.
    _last_gate_decision: Any = None

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying tool binary is present and runnable."""

    @abstractmethod
    def plan(self, task: Task) -> Command:
        """Translate a task into a concrete Command (no execution yet)."""

    @abstractmethod
    def execute(self, command: Command, env: ExecutionEnv) -> Finding:
        """Execute a Command in the given environment and return a Finding."""

    # ---------- shared safety-gate enforcement ----------

    @staticmethod
    def _command_key(command: Command, env: ExecutionEnv) -> str:
        """Stable content hash correlating a command to its review record."""
        import hashlib
        import json

        blob = json.dumps(
            {"adapter": command.adapter_name, "argv": command.argv, "env": env.value},
            sort_keys=True,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _gate_or_raise(
        self,
        command: Command,
        env: ExecutionEnv,
        error_cls: type[Exception],
    ) -> None:
        """Run the advertised 5-stage safety gate and enforce its verdict.

        APPROVE   -> return (caller proceeds to execute)
        DENY      -> raise ``error_cls`` (never execute)
        ESCALATE  -> execute only if an operator APPROVE is already recorded
                     for this command; otherwise enqueue a review (if a queue
                     is configured) and raise ``error_cls`` to block.
        """
        # Local import avoids a base<->safety_gate import cycle.
        from . import safety_gate

        decision = safety_gate.evaluate(command, env, context=self._gate_context)
        # Record for the driving runner's audit trail (populated before any
        # raise below, so blocked commands still surface their decision).
        self._last_gate_decision = decision
        if decision.final == safety_gate.Verdict.APPROVE:
            return
        if decision.final == safety_gate.Verdict.DENY:
            raise error_cls(
                "safety gate DENY: " + "; ".join(decision.reasons())
            )

        # ESCALATE — require an explicit operator approval for this command.
        key = self._command_key(command, env)
        rq = self._review_queue
        if rq is not None and rq.is_key_approved(key):
            return
        if rq is not None and not rq.has_pending_key(key):
            rq.enqueue(
                proposing_agent=self.name,
                action_kind="execute",
                summary=command.rationale,
                reasoning_chain=decision.reasons(),
                payload={"argv": list(command.argv), "env": env.value},
                dedup_key=key,
            )
        raise error_cls(
            "safety gate ESCALATE: execution blocked pending operator approval"
        )

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "available": self.is_available(),
        }
