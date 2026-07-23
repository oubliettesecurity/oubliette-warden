"""Tests for the Metasploit auxiliary-scanner adapter."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.codegen.base import ExecutionEnv, Task  # noqa: E402
from oubliette_warden.agents.codegen.msf_adapter import (  # noqa: E402
    MSFAuxAdapter,
    MSFPolicyError,
    MSFTargetError,
)
from oubliette_warden.agents.codegen.safety_gate import Verdict, evaluate  # noqa: E402


from oubliette_warden.agents.codegen.base import AttackTechnique, Command
from oubliette_warden.agents.codegen.safety_gate import DEFAULT_PIPELINE, GateContext
from oubliette_warden.agents.planner.planner import TaskGraph
from oubliette_warden.operator_ui.review_queue import ReviewQueue, ReviewVerdict


def _downstream(cmd, env):
    """Pin the five downstream stages (CRIT-1 prepends plan_consistency to the
    default path; these gate-integration checks target the downstream stages)."""
    return evaluate(cmd, env, pipeline=DEFAULT_PIPELINE)


def _ctx_for(task_id: str, targets: list[str], technique_ids: list[str]) -> GateContext:
    """Single-node plan context so plan_consistency APPROVEs an attributable command.

    operator_approved=True: default plan_trust is now 'anchored', so a task
    must carry operator approval to pass plan_consistency regardless of the
    downstream stage under test here.
    """
    node = Task(
        task_id=task_id,
        intent="gate-test",
        target_scope=targets,
        attck_technique_ids=technique_ids,
        operator_approved=True,
        metadata={},  # no phase -> adapter/phase check skipped
    )
    plan = TaskGraph(intent="t", target_scope=targets, nodes=[node], edges=[])
    return GateContext(plan=plan, completed_task_ids=set())


class FakeMSFClient:
    """Minimal fake msfrpcd client for unit tests."""

    def __init__(self, rows: list[dict] | None = None) -> None:
        self._rows = rows or []
        self.run_calls: list[tuple[str, dict]] = []

    def module_info(self, module: str) -> dict:
        return {"name": module, "type": "auxiliary"}

    def module_run(self, module: str, options: dict) -> dict:
        self.run_calls.append((module, options))
        return {"rows": self._rows, "task_id": "t-fake"}


# ---------- module-selection policy ----------


def test_default_module_is_portscan():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24"]))
    assert "auxiliary/scanner/portscan/tcp" in cmd.argv


def test_smb_intent_selects_smb_version():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="scan smb services", target_scope=["10.50.0.10"]))
    assert "auxiliary/scanner/smb/smb_version" in cmd.argv


def test_http_intent_selects_http_version():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="probe web services", target_scope=["10.50.0.30"]))
    assert "auxiliary/scanner/http/http_version" in cmd.argv


# ---------- target validation ----------


def test_plan_accepts_cidr_and_host_targets():
    a = MSFAuxAdapter()
    cmd = a.plan(
        Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24", "host.local"])
    )
    assert "10.50.0.0/24" in cmd.target_scope
    assert "host.local" in cmd.target_scope


def test_plan_rejects_target_with_shell_metachars():
    a = MSFAuxAdapter()
    with pytest.raises(MSFTargetError):
        a.plan(Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24; rm -rf /"]))


def test_plan_rejects_empty_scope():
    a = MSFAuxAdapter()
    with pytest.raises(MSFTargetError):
        a.plan(Task(task_id="t1", intent="enumerate", target_scope=[]))


# ---------- module policy ----------


def test_constructor_rejects_non_auxiliary_default_module():
    with pytest.raises(MSFPolicyError):
        MSFAuxAdapter(default_module="exploit/windows/smb/ms17_010_eternalblue")


def test_constructor_rejects_brute_login_module():
    with pytest.raises(MSFPolicyError):
        MSFAuxAdapter(default_module="auxiliary/scanner/ssh/ssh_login")


def test_constructor_rejects_non_allowed_category():
    with pytest.raises(MSFPolicyError):
        # category "voip" is not in the Phase I allow-list
        MSFAuxAdapter(default_module="auxiliary/scanner/voip/options")


def test_execute_rejects_live_env():
    a = MSFAuxAdapter(client=FakeMSFClient())
    cmd = a.plan(Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24"]))
    with pytest.raises(MSFPolicyError):
        a.execute(cmd, ExecutionEnv.LIVE)


def test_execute_rejects_lab_range_in_phase1():
    a = MSFAuxAdapter(client=FakeMSFClient())
    cmd = a.plan(Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24"]))
    with pytest.raises(MSFPolicyError):
        a.execute(cmd, ExecutionEnv.LAB_RANGE)


# ---------- safety-gate integration ----------


def test_emitted_command_passes_caldera_gate():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="smb enum", target_scope=["10.50.0.0/24"]))
    decision = _downstream(cmd, ExecutionEnv.CALDERA_ONLY)
    # llm_judge is a fail-closed stub (CRIT-3): ESCALATE, not silent APPROVE.
    assert decision.final == Verdict.ESCALATE
    assert all(
        s.verdict == Verdict.APPROVE for s in decision.stages if s.stage != "llm_judge"
    ), decision.reasons()


def test_emitted_command_blocked_when_env_is_live():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="smb enum", target_scope=["10.50.0.0/24"]))
    assert _downstream(cmd, ExecutionEnv.LIVE).final == Verdict.DENY


# ---------- execute + finding shape ----------


def test_execute_normalizes_results_and_extracts_cves():
    # llm_judge is a fail-closed stub (CRIT-3): every command now ESCALATEs
    # to operator review, so this adapter must be wired with a ReviewQueue
    # and get an explicit operator APPROVE before execute() proceeds.
    rows = [
        {"host": "10.50.0.10", "port": 445, "service": "smb",
         "info": "Windows SMB v1 fingerprinted -- known CVE-2017-0144"},
        {"host": "10.50.0.20", "port": 22, "service": "ssh",
         "info": "OpenSSH 8.2 banner"},
    ]
    client = FakeMSFClient(rows=rows)
    rq = ReviewQueue()
    a = MSFAuxAdapter(client=client, review_queue=rq)
    cmd = a.plan(Task(task_id="t1", intent="smb enum", target_scope=["10.50.0.0/24"]))
    # CRIT-1: attribution mandatory. Supply a matching plan context so
    # plan_consistency APPROVEs and the llm_judge stub is what ESCALATEs.
    a._gate_context = _ctx_for("t1", ["10.50.0.0/24"], ["T1135", "T1046"])

    with pytest.raises(MSFPolicyError, match="operator"):
        a.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    pending = rq.list_pending()
    assert len(pending) == 1
    rq.decide(pending[0].review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-1")

    finding = a.execute(cmd, ExecutionEnv.CALDERA_ONLY)

    assert finding.adapter_name == "msf-aux"
    assert "CVE-2017-0144" in finding.candidate_cves
    assert finding.parsed["rows"][0]["host"] == "10.50.0.10"
    assert client.run_calls == [
        ("auxiliary/scanner/smb/smb_version", {"RHOSTS": "10.50.0.0/24"})
    ]


def test_execute_without_client_is_unavailable():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="enumerate", target_scope=["10.50.0.0/24"]))
    with pytest.raises(MSFPolicyError):
        a.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert a.is_available() is False


def test_argv_shape_includes_module_and_rhosts():
    a = MSFAuxAdapter()
    cmd = a.plan(Task(task_id="t1", intent="rdp version", target_scope=["10.50.0.0/24"]))
    assert cmd.argv[0] == "msf-aux"
    assert cmd.argv[1] == "run"
    assert cmd.argv[2].startswith("auxiliary/scanner/")
    assert any(a.startswith("RHOSTS=") for a in cmd.argv[3:])


# ---------- CRITICAL: safety_gate.evaluate() is enforced on execute ----------


def test_execute_refuses_command_the_gate_denies():
    """A gate-DENYing command must never reach the RPC client."""
    client = FakeMSFClient()
    a = MSFAuxAdapter(client=client)
    # Attribute the command (CRIT-1) so the DENY under test genuinely comes from
    # pattern_detector's 'shutdown' token, not the fail-closed attribution stage.
    a._gate_context = _ctx_for("deny-1", ["10.0.0.1"], ["T1595"])
    # Valid auxiliary module (passes _enforce_phase1_policy), but the gate's
    # pattern_detector DENYs the 'shutdown' token.
    cmd = Command(
        adapter_name="msf-aux",
        argv=["msf-aux", "run", "auxiliary/scanner/portscan/tcp", "RHOSTS=10.0.0.1", "shutdown"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=60,
        rationale="test",
        task_id="deny-1",
    )
    with pytest.raises(MSFPolicyError, match="gate"):
        a.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert client.run_calls == []


def test_execute_escalate_blocks_until_operator_approval():
    rq = ReviewQueue()
    client = FakeMSFClient(rows=[{"host": "10.0.0.1", "info": "x"}])
    a = MSFAuxAdapter(client=client, review_queue=rq)
    # CRIT-1: attribution mandatory; supply context so mcp_guard's ESCALATE
    # (runtime > 1800) is what drives the review-queue path.
    a._gate_context = _ctx_for("esc-1", ["10.0.0.1"], ["T1046"])
    # runtime > 1800 -> mcp_guard ESCALATE.
    cmd = Command(
        adapter_name="msf-aux",
        argv=["msf-aux", "run", "auxiliary/scanner/portscan/tcp", "RHOSTS=10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1046"],
        is_active_probe=True,
        expected_runtime_seconds=3600,
        rationale="long scan",
        task_id="esc-1",
    )
    with pytest.raises(MSFPolicyError, match="operator"):
        a.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert client.run_calls == []
    pending = rq.list_pending()
    assert len(pending) == 1

    rq.decide(pending[0].review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-1")
    finding = a.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert len(client.run_calls) == 1
    assert finding.adapter_name == "msf-aux"
