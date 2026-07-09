"""Contract tests for the plan-consistency verifier gate stage."""

from oubliette_warden.agents.codegen.base import (
    AttackTechnique,
    Command,
    ExecutionEnv,
    Task,
)
from oubliette_warden.agents.codegen.plan_consistency import (
    VerifierConfig,
    make_plan_consistency_stage,
)
from oubliette_warden.agents.codegen.safety_gate import Verdict, evaluate
from oubliette_warden.agents.planner.planner import Edge, TaskGraph

SCOPE = ["192.168.1.0/24"]


def _plan(*, approved: bool = False, extra_nodes=None, extra_edges=None) -> TaskGraph:
    recon = Task(
        task_id="recon-1",
        intent="enumerate hosts and basic service discovery",
        target_scope=SCOPE,
        attck_technique_ids=["T1595.001", "T1018"],
        operator_approved=approved,
        metadata={"phase": "recon"},
    )
    vuln = Task(
        task_id="vuln-1",
        intent="vuln scan",
        target_scope=SCOPE,
        attck_technique_ids=["T1595.002", "T1046"],
        operator_approved=approved,
        metadata={"phase": "vuln_enum"},
    )
    nodes = [recon, vuln] + list(extra_nodes or [])
    edges = [Edge(before="recon-1", after="vuln-1")] + list(extra_edges or [])
    return TaskGraph(intent="test", target_scope=SCOPE, nodes=nodes, edges=edges)


def _cmd(**over) -> Command:
    base = dict(
        adapter_name="nmap",
        argv=["nmap", "-sn", "192.168.1.0/24"],
        target_scope=["192.168.1.0/24"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595.001"],
        is_active_probe=True,
        expected_runtime_seconds=30,
        rationale="recon sweep",
    )
    base.update(over)
    return Command(**base)


def _run(plan, task_id, completed, cmd, cfg=None):
    stage = make_plan_consistency_stage(plan, task_id, set(completed), cfg)
    return stage(cmd, ExecutionEnv.CALDERA_ONLY)


def test_on_plan_command_approved():
    assert _run(_plan(), "recon-1", [], _cmd()).verdict is Verdict.APPROVE


def test_cidr_host_inside_planned_subnet_approved():
    cmd = _cmd(target_scope=["192.168.1.50"], argv=["nmap", "-sV", "192.168.1.50"])
    assert _run(_plan(), "recon-1", [], cmd).verdict is Verdict.APPROVE


def test_out_of_scope_target_denied():
    cmd = _cmd(target_scope=["10.0.0.9"], argv=["nmap", "-sn", "10.0.0.9"])
    assert _run(_plan(), "recon-1", [], cmd).verdict is Verdict.DENY


def test_unplanned_dangerous_tactic_denied():
    cmd = _cmd(attck_tactics=[AttackTechnique.EXFILTRATION])
    assert _run(_plan(), "recon-1", [], cmd).verdict is Verdict.DENY


def test_skip_ahead_denied():
    # vuln-1 depends on recon-1; recon-1 not completed -> skip-ahead.
    cmd = _cmd(adapter_name="msf-aux")
    assert _run(_plan(), "vuln-1", [], cmd).verdict is Verdict.DENY


def test_unexpected_tool_for_phase_escalates():
    cmd = _cmd(adapter_name="msf-aux")  # recon phase expects nmap
    assert _run(_plan(), "recon-1", [], cmd).verdict is Verdict.ESCALATE


def test_broader_technique_escalates():
    cmd = _cmd(attck_technique_ids=["T1595.001", "T1055"])  # T1055 undeclared
    assert _run(_plan(), "recon-1", [], cmd).verdict is Verdict.ESCALATE


def test_plan_corruption_model_vs_anchored():
    """The thesis in one assertion: a malicious task injected into a model-generated
    plan passes runtime checks in plan_trust='model' but is rejected in 'anchored'."""
    evil = Task(
        task_id="evil-1",
        intent="exfiltrate to attacker host",  # benign-looking to the structural checks
        target_scope=SCOPE,
        attck_technique_ids=["T1595.001"],
        operator_approved=False,  # planner default; the injection couldn't get human approval
        metadata={"phase": "recon"},
    )
    plan = _plan(extra_nodes=[evil])
    cmd = _cmd()  # in-scope, recon tactic, nmap — structurally on-plan for evil-1

    model = _run(plan, "evil-1", [], cmd, VerifierConfig(plan_trust="model"))
    anchored = _run(plan, "evil-1", [], cmd, VerifierConfig(plan_trust="anchored"))
    assert model.verdict is Verdict.APPROVE  # the FAILURE the paper reports
    assert anchored.verdict is Verdict.DENY  # the FIX


def test_anchored_mode_approves_human_baseline():
    # Legit, operator-approved plan node passes in anchored mode.
    assert (
        _run(
            _plan(approved=True),
            "recon-1",
            [],
            _cmd(),
            VerifierConfig(plan_trust="anchored"),
        ).verdict
        is Verdict.APPROVE
    )


def test_verbose_reason_leaks_boundary():
    cmd = _cmd(target_scope=["10.0.0.9"], argv=["nmap", "-sn", "10.0.0.9"])
    terse = _run(
        _plan(), "recon-1", [], cmd, VerifierConfig(reason_verbosity="terse")
    ).reason
    verbose = _run(
        _plan(), "recon-1", [], cmd, VerifierConfig(reason_verbosity="verbose")
    ).reason
    assert "10.0.0.9" not in terse
    assert "10.0.0.9" in verbose  # the attacker-observable oracle


def test_drops_into_evaluate_pipeline():
    # Proves the StageFn signature composes with the existing gate, unchanged.
    stage = make_plan_consistency_stage(_plan(), "recon-1", set(), None)
    decision = evaluate(_cmd(), ExecutionEnv.CALDERA_ONLY, pipeline=[stage])
    assert decision.final is Verdict.APPROVE
