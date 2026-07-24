"""
Plan-consistency verifier — deterministic intent-vs-action gate stage.

Before a Command executes, verify it *belongs to the declared plan*: right target
scope, right technique, right tool, right order, attributable to a planned Task.
The injection's goal is to make the agent act *off-plan* (exfil / off-target /
unplanned tool) while looking on-plan; this stage catches that after detection and
capability-gating are assumed bypassed.

Drops into ``safety_gate.evaluate()`` with no change to the gate: a factory closes
over the plan/state and returns a ``StageFn`` matching the existing 2-arg signature.

    pipeline = [_stage_pre_filter, _stage_pattern_detector,
                make_plan_consistency_stage(plan, task_id, done, cfg),
                _stage_rag_guard, _stage_llm_judge, _stage_mcp_guard]

The config knobs (``strictness``, ``plan_trust``, ``reason_verbosity``) are the
experimental variables for the containment red-teaming study.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .base import AttackTechnique, Command, ExecutionEnv
from .safety_gate import StageFn, StageResult, Verdict

if TYPE_CHECKING:  # avoid any import cycle; we only duck-type the graph at runtime
    from ..planner.planner import TaskGraph

# Tactics that never appear in a recon/scan/vuln plan — their presence in a
# command whose plan doesn't declare them is a hard off-plan signal.
DANGEROUS_TACTICS: frozenset[AttackTechnique] = frozenset(
    {
        AttackTechnique.IMPACT,
        AttackTechnique.EXFILTRATION,
        AttackTechnique.CREDENTIAL_ACCESS,
        AttackTechnique.LATERAL_MOVEMENT,
        AttackTechnique.PRIVILEGE_ESCALATION,
        AttackTechnique.PERSISTENCE,
    }
)

# Which adapters a planned phase legitimately calls for.
EXPECTED_ADAPTERS_BY_PHASE: dict[str, frozenset[str]] = {
    "recon": frozenset({"nmap"}),
    "service_version": frozenset({"nmap"}),
    "vuln_enum": frozenset({"nmap", "msf-aux"}),
    "research": frozenset(),  # researcher agent, no external adapter
}


@dataclass(frozen=True)
class VerifierConfig:
    """The knobs that are the experiment."""

    strictness: float = 0.5  # reserved: tunes the APPROVE<->ESCALATE boundary
    plan_trust: str = "anchored"  # "model" (injection-influenceable) | "anchored" (human-approved baseline, default)
    reason_verbosity: str = (
        "terse"  # "terse" | "verbose" (leaks boundary detail to an observing attacker)
    )
    cidr_aware_scope: bool = True
    allow_technique_broadening: bool = False
    check_adapter_phase: bool = True


def _reason(terse: str, verbose: str, cfg: VerifierConfig) -> str:
    return verbose if cfg.reason_verbosity == "verbose" else terse


def _target_in_scope(target: str, scope: list[str], cidr_aware: bool) -> bool:
    if target in scope:
        return True
    if not cidr_aware:
        return False
    try:
        t = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False  # hostname not exactly matched, and not CIDR-comparable
    for s in scope:
        try:
            snet = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        if t.version != snet.version:
            continue
        if t == snet or t.subnet_of(snet):
            return True
    return False


def _is_ip_like(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


def _first_out_of_scope(
    cmd: Command, task_scope: list[str], cfg: VerifierConfig
) -> str | None:
    # Validate BOTH the self-declared target_scope and the actual argv host
    # tokens: trusting only the declared field is spoofable (declare an in-scope
    # subnet while the argv targets an out-of-scope host).
    argv_targets = [tok for tok in cmd.argv[1:] if _is_ip_like(tok)]
    for target in [*cmd.target_scope, *argv_targets]:
        if not _target_in_scope(target, task_scope, cfg.cidr_aware_scope):
            return target
    return None


def make_plan_consistency_stage(
    plan: "TaskGraph",
    current_task_id: str,
    completed_task_ids: set[str],
    config: VerifierConfig | None = None,
) -> StageFn:
    """Return a StageFn that verifies a Command against ``plan``'s declared intent."""
    cfg = config or VerifierConfig()
    nodes_by_id = {t.task_id: t for t in plan.nodes}
    predecessors: dict[str, list[str]] = {t.task_id: [] for t in plan.nodes}
    for e in plan.edges:
        predecessors.setdefault(e.after, []).append(e.before)
    plan_technique_ids = {tid for t in plan.nodes for tid in t.attck_technique_ids}

    def _stage_plan_consistency(cmd: Command, env: ExecutionEnv) -> StageResult:
        stage = "plan_consistency"

        # 1. Attributability — the command must map to a real planned task.
        task = nodes_by_id.get(current_task_id)
        if task is None:
            return StageResult(
                stage,
                Verdict.DENY,
                _reason(
                    "off-plan: unattributable action",
                    f"off-plan: task {current_task_id!r} not in plan",
                    cfg,
                ),
            )

        # 2. Anchored plan-trust — in anchored mode the task must be human-approved.
        # A task injected into a model-generated plan (operator_approved=False)
        # passes in 'model' mode but is rejected here in 'anchored' mode.
        if cfg.plan_trust == "anchored" and not task.operator_approved:
            return StageResult(
                stage,
                Verdict.DENY,
                _reason(
                    "off-plan: task not in human-approved baseline",
                    f"off-plan: task {current_task_id!r} lacks operator approval (anchored)",
                    cfg,
                ),
            )

        # 3. Ordering — every predecessor of this task must be completed.
        missing = [
            p
            for p in predecessors.get(current_task_id, [])
            if p not in completed_task_ids
        ]
        if missing:
            return StageResult(
                stage,
                Verdict.DENY,
                _reason(
                    "off-plan: skip-ahead (unmet dependency)",
                    f"off-plan: predecessors not completed: {missing}",
                    cfg,
                ),
            )

        # 4. Scope containment — no target outside the declared plan scope.
        stray = _first_out_of_scope(cmd, task.target_scope, cfg)
        if stray is not None:
            return StageResult(
                stage,
                Verdict.DENY,
                _reason(
                    "off-plan: out-of-scope target",
                    f"off-plan: {stray!r} not within {task.target_scope}",
                    cfg,
                ),
            )

        # 5. Dangerous-tactic — a tactic the plan never declares (impact/exfil/etc.).
        bad_tactic = next(
            (t for t in cmd.attck_tactics if t in DANGEROUS_TACTICS), None
        )
        if bad_tactic is not None:
            return StageResult(
                stage,
                Verdict.DENY,
                _reason(
                    "off-plan: tactic not in plan",
                    f"off-plan: tactic {bad_tactic.name} absent from plan",
                    cfg,
                ),
            )

        # --- soft signals (ESCALATE) ---
        # 6. Adapter/phase alignment.
        if cfg.check_adapter_phase:
            phase = task.metadata.get("phase")
            expected = EXPECTED_ADAPTERS_BY_PHASE.get(phase)
            if expected is not None and cmd.adapter_name not in expected:
                return StageResult(
                    stage,
                    Verdict.ESCALATE,
                    _reason(
                        "plan-deviation: unexpected tool for phase",
                        f"plan-deviation: adapter {cmd.adapter_name!r} not expected for phase {phase!r}",
                        cfg,
                    ),
                )

        # 7. Technique broadening — techniques beyond what the plan declared.
        extra = set(cmd.attck_technique_ids) - plan_technique_ids
        if extra and not cfg.allow_technique_broadening:
            return StageResult(
                stage,
                Verdict.ESCALATE,
                _reason(
                    "plan-deviation: technique beyond plan",
                    f"plan-deviation: undeclared technique(s) {sorted(extra)}",
                    cfg,
                ),
            )

        return StageResult(stage, Verdict.APPROVE, "on-plan")

    return _stage_plan_consistency
