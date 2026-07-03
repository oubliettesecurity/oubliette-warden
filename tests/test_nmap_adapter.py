"""Unit tests for the Nmap CommandAdapter (no nmap binary required)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.codegen.base import (  # noqa: E402
    AttackTechnique,
    Command,
    ExecutionEnv,
    Task,
)
from oubliette_warden.agents.codegen.nmap_adapter import (  # noqa: E402
    NmapAdapter,
    NmapPolicyError,
    NmapTargetError,
)


from oubliette_warden.agents.codegen import nmap_adapter as nmap_mod
from oubliette_warden.operator_ui.review_queue import ReviewQueue, ReviewVerdict


@pytest.fixture
def adapter(tmp_path):
    return NmapAdapter(scratch_dir=tmp_path)


def test_validate_targets_accepts_cidr_and_host(adapter):
    out = NmapAdapter._validate_targets(["10.50.0.0/24", "host01.example", "fe80::1"])
    assert "10.50.0.0/24" in out
    assert "host01.example" in out


def test_validate_targets_rejects_garbage():
    with pytest.raises(NmapTargetError):
        NmapAdapter._validate_targets(["10.0.0.1; rm -rf /"])


def test_validate_targets_rejects_empty():
    with pytest.raises(NmapTargetError):
        NmapAdapter._validate_targets([])


def test_plan_for_enumeration(adapter):
    task = Task(
        task_id="t1",
        intent="enumerate hosts on range",
        target_scope=["10.50.0.0/24"],
    )
    cmd = adapter.plan(task)
    assert cmd.adapter_name == "nmap"
    assert "-sV" in cmd.argv
    assert "10.50.0.0/24" in cmd.argv
    assert AttackTechnique.RECONNAISSANCE in cmd.attck_tactics
    assert any(t.startswith("T15") for t in cmd.attck_technique_ids)
    assert not cmd.is_impact_class()


def test_plan_for_vuln_intent_includes_vuln_scripts(adapter):
    task = Task(task_id="t2", intent="vuln scan", target_scope=["192.168.1.10"])
    cmd = adapter.plan(task)
    idx = cmd.argv.index("--script")
    scripts = cmd.argv[idx + 1]
    assert "vuln" in scripts


def test_execute_rejects_non_caldera_env(adapter):
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "-sV", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=10,
        rationale="test",
    )
    with pytest.raises(NmapPolicyError, match="CALDERA_ONLY"):
        adapter.execute(cmd, ExecutionEnv.LIVE)


def test_execute_rejects_impact_class(adapter):
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.IMPACT],
        attck_technique_ids=["T1499"],
        is_active_probe=True,
        expected_runtime_seconds=10,
        rationale="test",
    )
    with pytest.raises(NmapPolicyError, match="Impact"):
        adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)


def test_execute_rejects_intrusive_nse(adapter):
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "--script", "intrusive,exploit", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=10,
        rationale="test",
    )
    with pytest.raises(NmapPolicyError, match="intrusive"):
        adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)


def test_parse_xml_extracts_hosts_ports_cves(adapter):
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.50.0.5" addrtype="ipv4"/>
        <ports>
          <port portid="22" protocol="tcp">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="7.4"/>
            <script id="vulners" output="OpenSSH 7.4 CVE-2018-15473 CVE-2016-6515"/>
          </port>
          <port portid="80" protocol="tcp">
            <state state="open"/>
            <service name="http" product="nginx" version="1.14"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    parsed = NmapAdapter._parse_xml(xml)
    assert len(parsed["hosts"]) == 1
    host = parsed["hosts"][0]
    assert host["address"] == "10.50.0.5"
    assert len(host["ports"]) == 2
    assert "CVE-2018-15473" in host["cves"]
    assert "CVE-2016-6515" in host["cves"]


def test_parse_xml_handles_garbage():
    parsed = NmapAdapter._parse_xml("not xml at all")
    assert parsed.get("parse_error") is True


def test_parse_xml_empty_string_returns_no_hosts():
    parsed = NmapAdapter._parse_xml("")
    assert parsed == {"hosts": []}


def test_summarize_counts_open_ports():
    parsed = {
        "hosts": [
            {"address": "h1", "ports": [{"state": "open"}, {"state": "closed"}], "cves": []},
            {"address": "h2", "ports": [{"state": "open"}], "cves": []},
        ]
    }
    s = NmapAdapter._summarize(parsed, returncode=0)
    assert "2 hosts" in s
    assert "2 open" in s


# ---------- CRITICAL: safety_gate.evaluate() is enforced on execute ----------


def test_execute_refuses_command_the_gate_denies(adapter, monkeypatch):
    """A command the 5-stage gate DENYs must never reach subprocess."""
    called = {"ran": False}

    def _boom(*_a, **_k):
        called["ran"] = True
        raise AssertionError("subprocess.run must not be called on a gated command")

    monkeypatch.setattr(nmap_mod.subprocess, "run", _boom)
    monkeypatch.setattr(adapter, "is_available", lambda: True)

    # Passes _enforce_phase1_policy (caldera, non-impact, no --script) but the
    # gate's pattern_detector DENYs the 'shutdown' token.
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "-sV", "shutdown", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=10,
        rationale="test",
    )
    with pytest.raises(NmapPolicyError, match="gate"):
        adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert called["ran"] is False


def test_execute_escalate_blocks_until_operator_approval(tmp_path, monkeypatch):
    """ESCALATE verdicts are routed to the ReviewQueue and block until APPROVE."""
    rq = ReviewQueue()
    adapter = NmapAdapter(scratch_dir=tmp_path, review_queue=rq)

    ran = {"count": 0}

    def _fake_run(*_a, **_k):
        ran["count"] += 1

        class _P:
            stdout = ""
            returncode = 0

        return _P()

    monkeypatch.setattr(nmap_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(adapter, "is_available", lambda: True)

    # runtime > 1800 -> mcp_guard ESCALATE (policy stage passes it through).
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "-sV", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=3600,
        rationale="long scan",
    )

    # First attempt: no operator approval yet -> blocked + enqueued.
    with pytest.raises(NmapPolicyError, match="operator"):
        adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert ran["count"] == 0
    pending = rq.list_pending()
    assert len(pending) == 1

    # Operator approves that review.
    rq.decide(
        pending[0].review_id,
        verdict=ReviewVerdict.APPROVE,
        operator_id="op-1",
    )

    # Second attempt: approval recorded for this command -> executes.
    finding = adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert ran["count"] == 1
    assert finding.adapter_name == "nmap"


# ---------- HIGH: NSE allow-list + target-injection hardening ----------


def test_enforce_policy_rejects_non_allowlisted_nse_category(adapter):
    """fuzzer/malware/external/auth/broadcast were silently allowed before."""
    for cat in ("fuzzer", "malware", "external", "auth", "broadcast"):
        cmd = Command(
            adapter_name="nmap",
            argv=["nmap", "--script", cat, "10.0.0.1"],
            target_scope=["10.0.0.1"],
            attck_tactics=[AttackTechnique.RECONNAISSANCE],
            attck_technique_ids=["T1595"],
            is_active_probe=True,
            expected_runtime_seconds=10,
            rationale="test",
        )
        with pytest.raises(NmapPolicyError):
            NmapAdapter._enforce_phase1_policy(cmd, ExecutionEnv.CALDERA_ONLY)


def test_enforce_policy_inspects_all_script_occurrences(adapter):
    """A second --script must not slip a forbidden category past the check."""
    cmd = Command(
        adapter_name="nmap",
        argv=["nmap", "--script", "safe", "--script", "malware", "10.0.0.1"],
        target_scope=["10.0.0.1"],
        attck_tactics=[AttackTechnique.RECONNAISSANCE],
        attck_technique_ids=["T1595"],
        is_active_probe=True,
        expected_runtime_seconds=10,
        rationale="test",
    )
    with pytest.raises(NmapPolicyError):
        NmapAdapter._enforce_phase1_policy(cmd, ExecutionEnv.CALDERA_ONLY)


def test_planned_commands_pass_their_own_policy(adapter):
    """The adapter must not refuse the commands it legitimately emits."""
    for intent in ("enumerate hosts", "service version scan", "vuln scan"):
        cmd = adapter.plan(Task(task_id="t", intent=intent, target_scope=["10.0.0.1"]))
        NmapAdapter._enforce_phase1_policy(cmd, ExecutionEnv.CALDERA_ONLY)


def test_validate_targets_rejects_flag_like_token():
    """A target starting with '-' could inject a second --script into argv."""
    with pytest.raises(NmapTargetError):
        NmapAdapter._validate_targets(["--script"])
    with pytest.raises(NmapTargetError):
        NmapAdapter._validate_targets(["-oX"])


# ---------- MEDIUM: scratch XML filename must be unique per invocation ----------


def test_scratch_paths_are_unique_for_identical_argv(adapter):
    argv = ["nmap", "-sV", "10.0.0.1"]
    p1 = adapter._scratch_path(argv)
    p2 = adapter._scratch_path(argv)
    assert p1 != p2
