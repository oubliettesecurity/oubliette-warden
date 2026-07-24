"""
End-to-end smoke test: planner -> nmap.plan() -> safety gate -> approval ->
analyst ranking.

This proves the Phase I demo loop works in pure-Python without nmap, CALDERA,
or an LLM. Replaces the executor with a no-op (we never actually run nmap in
unit tests). The point of this test is to confirm the *contract* between
agents holds — not to benchmark scan latency.
"""

from __future__ import annotations

import dataclasses
import sys
from itertools import count
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.analysis.analyst import CyberAnalyst  # noqa: E402
from oubliette_warden.agents.analysis.models import AssetProfile  # noqa: E402
from oubliette_warden.agents.codegen.base import ExecutionEnv
from oubliette_warden.agents.codegen.nmap_adapter import NmapAdapter
from oubliette_warden.agents.codegen.safety_gate import (
    DEFAULT_PIPELINE,
    GateContext,
    Verdict,
    evaluate,
)
from oubliette_warden.agents.planner.planner import Planner


def _downstream(cmd, env):
    """Evaluate the five downstream deterministic stages explicitly.

    CRIT-1 made the default pipeline prepend a fail-closed plan_consistency
    stage; these planner->codegen->analyst contract tests target the downstream
    stages, so they pin DEFAULT_PIPELINE. Attribution wiring is covered by
    test_full_pipeline_threads_plan_context below and by test_safety_gate.py.
    """
    return evaluate(cmd, env, pipeline=DEFAULT_PIPELINE)


# Canonical Nmap XML the simulated CALDERA range would return for the
# 10.50.0.0/24 enumeration scan. Kept minimal but realistic: one SMB box
# flagged by `vulners` with CVE candidates, one OpenSSH host, one HTTP host.
NMAP_FIXTURE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.50.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows SMB"/>
        <script id="vulners" output="CVE-2017-0144"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.50.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH 8.2"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.50.0.30" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def planner():
    counters: dict[str, count[int]] = {}
    def _id(prefix):
        counters[prefix] = counters.get(prefix, count(1))
        return f"{prefix}-{next(counters[prefix]):03d}"
    return Planner(id_factory=_id)


def test_full_pipeline_for_enumerate_intent(planner, tmp_path):
    graph = planner.plan("enumerate hosts on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)

    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            continue
        cmd = nmap.plan(task)
        decision = _downstream(cmd, ExecutionEnv.CALDERA_ONLY)
        # llm_judge is a fail-closed stub (CRIT-3): a structurally clean
        # command still ESCALATEs to operator review rather than auto-running.
        assert decision.final == Verdict.ESCALATE, decision.reasons()
        assert all(
            s.verdict == Verdict.APPROVE for s in decision.stages if s.stage != "llm_judge"
        ), decision.reasons()
        assert any(arg == "10.50.0.0/24" for arg in cmd.argv)


def test_full_pipeline_blocks_when_env_is_live(planner, tmp_path):
    graph = planner.plan("enumerate hosts on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)
    task = graph.topological_order()[0]
    cmd = nmap.plan(task)
    decision = _downstream(cmd, ExecutionEnv.LIVE)
    assert decision.final == Verdict.DENY


def test_vuln_scan_intent_produces_research_handoff(planner, tmp_path):
    graph = planner.plan("vuln scan against 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)
    research_nodes = [n for n in graph.nodes if n.metadata.get("phase") == "research"]
    assert research_nodes, "vuln_scan kind must emit a research handoff node"

    # Every non-research node must produce a structurally clean Nmap command
    # (deterministic stages APPROVE); llm_judge's fail-closed stub still
    # routes it to operator review (CRIT-3).
    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            continue
        cmd = nmap.plan(task)
        decision = _downstream(cmd, ExecutionEnv.CALDERA_ONLY)
        assert decision.final == Verdict.ESCALATE, decision.reasons()
        assert all(
            s.verdict == Verdict.APPROVE for s in decision.stages if s.stage != "llm_judge"
        ), decision.reasons()


def test_planner_emits_attck_tags_visible_to_safety_gate(planner, tmp_path):
    graph = planner.plan("identify service versions on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)
    for task in graph.topological_order():
        cmd = nmap.plan(task)
        assert cmd.attck_technique_ids, "every emitted command must carry ATT&CK tags"
        decision = _downstream(cmd, ExecutionEnv.CALDERA_ONLY)
        # llm_judge fail-closed stub (CRIT-3): ESCALATE, not silent APPROVE.
        assert decision.final == Verdict.ESCALATE


# ---------- planner -> codegen -> safety -> analysis (the §2 Obj 3 loop) ----------


def test_full_pipeline_routes_scan_output_to_analyst(planner, tmp_path):
    """Closes the §2 Objective 3 end-to-end claim:
    planner emits enumerate task → CodeGen emits Nmap command → safety
    APPROVE → simulated Nmap XML returns → Cyber Analyst produces a ranked
    finding list with reasoning chains.
    """
    graph = planner.plan("enumerate hosts on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)

    # Plan + gate every non-research node. llm_judge fail-closed stub
    # (CRIT-3) means these ESCALATE to operator review rather than
    # auto-APPROVE; the deterministic stages are still clean.
    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            continue
        cmd = nmap.plan(task)
        decision = _downstream(cmd, ExecutionEnv.CALDERA_ONLY)
        assert decision.final == Verdict.ESCALATE, decision.reasons()
        assert all(
            s.verdict == Verdict.APPROVE for s in decision.stages if s.stage != "llm_judge"
        ), decision.reasons()

    # Simulated execution returns the fixture XML; analyst consumes it.
    analyst = CyberAnalyst()
    findings = analyst.analyze_nmap_xml(
        NMAP_FIXTURE_XML,
        cve_cvss_lookup={"CVE-2017-0144": 8.1},
    )
    assert findings, "analyst must produce at least one ranked finding"

    # Top finding should be the SMB host with EternalBlue.
    top = findings[0]
    assert "445" in top.service_summary
    assert "CVE-2017-0144" in top.candidate_cves
    assert top.risk.composite > 0
    # Reasoning chain visible to the audit log.
    assert any("risk score derived" in step for step in top.reasoning_chain)
    assert any(step.startswith("ranked 1/") for step in top.reasoning_chain)


def test_analyst_respects_asset_profile_in_e2e(planner, tmp_path):
    """Operator-supplied asset criticality must influence rank order even
    when the higher-criticality host has a less-exploitable service."""
    graph = planner.plan("enumerate hosts on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)
    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            continue
        cmd = nmap.plan(task)
        # llm_judge fail-closed stub (CRIT-3): ESCALATE, not silent APPROVE.
        assert _downstream(cmd, ExecutionEnv.CALDERA_ONLY).final == Verdict.ESCALATE

    # Make the SSH host mission-critical; the SMB and HTTP hosts trivial.
    # Top finding must shift to SSH even though SMB has higher service prior
    # and HTTP has middling prior with a stock baseline CVSS.
    profiles = {
        "10.50.0.20": AssetProfile(address="10.50.0.20", criticality=0.99, role="kdc"),
        "10.50.0.10": AssetProfile(address="10.50.0.10", criticality=0.05, role="test-vm"),
        "10.50.0.30": AssetProfile(address="10.50.0.30", criticality=0.05, role="dmz-stub"),
    }
    analyst = CyberAnalyst()
    findings = analyst.analyze_nmap_xml(
        NMAP_FIXTURE_XML,
        asset_profiles=profiles,
        cve_cvss_lookup={"CVE-2017-0144": 8.1},
    )
    top = findings[0]
    assert top.asset_address == "10.50.0.20"


# ---------- CRIT-1: attribution threads end-to-end through the default gate ----------


def test_full_pipeline_threads_plan_context(planner, tmp_path):
    """With a GateContext threaded from the plan (as the orchestrator supplies),
    the default gate path runs plan_consistency FIRST and never fails closed:
    each attributable, in-order, operator-approved command is admitted by
    attribution (the run may still ESCALATE downstream via the llm_judge stub,
    but plan_consistency never DENYs an on-plan command). Default plan_trust is
    now 'anchored', so the plan is stamped operator_approved=True here to model
    the human sign-off a real orchestrator would obtain before executing it —
    without that, anchored mode DENYs every task by design (see
    test_full_pipeline_without_context_fails_closed's sibling in
    test_plan_consistency.py / test_safety_gate.py). This is the wired path
    CRIT-1 delivers."""
    graph = planner.plan("vuln scan against 10.50.0.0/24")
    graph = dataclasses.replace(
        graph,
        nodes=[dataclasses.replace(t, operator_approved=True) for t in graph.nodes],
    )
    nmap = NmapAdapter(scratch_dir=tmp_path)

    completed: set[str] = set()
    saw_plan_consistency = False
    for task in graph.topological_order():
        if task.metadata.get("phase") == "research":
            completed.add(task.task_id)
            continue
        cmd = nmap.plan(task)
        assert cmd.task_id == task.task_id  # adapter populated attribution
        context = GateContext(plan=graph, completed_task_ids=set(completed))
        decision = evaluate(cmd, ExecutionEnv.CALDERA_ONLY, context=context)

        by_stage = {s.stage: s.verdict for s in decision.stages}
        assert "plan_consistency" in by_stage
        saw_plan_consistency = True
        # attribution admits the on-plan command (never DENY on the wired path);
        # the FIRST stage is plan_consistency.
        assert decision.stages[0].stage == "plan_consistency"
        assert by_stage["plan_consistency"] != Verdict.DENY
        completed.add(task.task_id)

    assert saw_plan_consistency


def test_full_pipeline_without_context_fails_closed(planner, tmp_path):
    """The same commands, evaluated on the default path WITHOUT plan context,
    are denied as unattributable — no command executes without plan attribution."""
    graph = planner.plan("enumerate hosts on 10.50.0.0/24")
    nmap = NmapAdapter(scratch_dir=tmp_path)
    task = graph.topological_order()[0]
    cmd = nmap.plan(task)
    decision = evaluate(cmd, ExecutionEnv.CALDERA_ONLY)  # no context
    assert decision.final == Verdict.DENY
    assert any("unattributable" in s.reason for s in decision.stages)
