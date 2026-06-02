"""Tests for the Cyber Analysis agent."""

from __future__ import annotations

import sys
from itertools import count
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.analysis.analyst import CyberAnalyst  # noqa: E402
from oubliette_warden.agents.analysis.models import AssetProfile, RiskScore  # noqa: E402
from oubliette_warden.agents.analysis.nmap_ingest import (  # noqa: E402
    NmapXMLParseError,
    parse_nmap_xml,
)
from oubliette_warden.agents.analysis.ranker import score  # noqa: E402


NMAP_XML_FIXTURE = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.50.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows SMB"/>
        <script id="vulners" output="CVE-2017-0144 CVE-2017-0145"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH 8.2"/>
      </port>
      <port protocol="tcp" portid="135">
        <state state="closed"/>
        <service name="msrpc"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.50.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

EMPTY_REPORT = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.50.0.30" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


# ---------- parse_nmap_xml ----------


def test_parse_empty_input_returns_empty_list():
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml("   \n\t") == []


def test_parse_skips_hosts_without_ports():
    obs = parse_nmap_xml(EMPTY_REPORT)
    assert obs == []


def test_parse_only_emits_open_ports():
    obs = parse_nmap_xml(NMAP_XML_FIXTURE)
    # 3 open: 445 + 22 + 80 (the 135/closed port is skipped)
    assert len(obs) == 3
    ports = sorted((o.host_address, o.port) for o in obs)
    assert ports == [("10.50.0.10", 22), ("10.50.0.10", 445), ("10.50.0.20", 80)]


def test_parse_surfaces_cves_from_script_output():
    obs = parse_nmap_xml(NMAP_XML_FIXTURE)
    smb = next(o for o in obs if o.port == 445)
    assert smb.candidate_cves == ["CVE-2017-0144", "CVE-2017-0145"]
    ssh = next(o for o in obs if o.port == 22)
    assert ssh.candidate_cves == []


def test_parse_tags_attck_from_service_class():
    obs = parse_nmap_xml(NMAP_XML_FIXTURE)
    smb = next(o for o in obs if o.port == 445)
    assert smb.attck_technique_ids  # microsoft-ds → has tags
    http = next(o for o in obs if o.port == 80)
    assert "T1071.001" in http.attck_technique_ids


def test_parse_rejects_malformed_xml():
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml("<this is not closed")


# ---------- ranker.score ----------


def test_score_known_service_uses_service_prior():
    rs = score(service="ssh", candidate_cves=[])
    assert rs.exploitability == pytest.approx(0.30)
    assert rs.cvss == pytest.approx(3.5)
    assert "ssh" in rs.reasoning
    assert "no CVE evidence" in rs.reasoning


def test_score_with_cve_lookup_uses_max_cvss():
    rs = score(
        service="microsoft-ds",
        candidate_cves=["CVE-2017-0144", "CVE-2017-0145"],
        cve_cvss_lookup={"CVE-2017-0144": 8.1, "CVE-2017-0145": 9.3},
    )
    assert rs.cvss == pytest.approx(9.3)
    # CVE present raises exploitability floor.
    assert rs.exploitability >= 0.60


def test_score_unknown_service_falls_back_to_priors():
    rs = score(service="totally-made-up", candidate_cves=[])
    assert rs.exploitability == pytest.approx(0.40)  # UNKNOWN_EXPLOITABILITY_PRIOR
    assert rs.cvss == pytest.approx(4.0)  # UNKNOWN_BASELINE_CVSS


def test_score_rejects_out_of_range_inputs():
    with pytest.raises(ValueError):
        RiskScore(exploitability=1.5, asset_criticality=0.5, cvss=5.0, reasoning="x")
    with pytest.raises(ValueError):
        RiskScore(exploitability=0.5, asset_criticality=0.5, cvss=11.0, reasoning="x")


def test_composite_is_monotone():
    low = score(service="ssh", candidate_cves=[], asset_criticality=0.2).composite
    high = score(service="ssh", candidate_cves=[], asset_criticality=0.9).composite
    assert high > low


# ---------- CyberAnalyst end-to-end ----------


@pytest.fixture
def analyst():
    counter = count(1)
    return CyberAnalyst(id_factory=lambda: f"af-{next(counter):04d}")


def test_analyst_ranks_smb_above_ssh_for_same_host(analyst):
    findings = analyst.analyze_nmap_xml(
        NMAP_XML_FIXTURE,
        cve_cvss_lookup={"CVE-2017-0144": 8.1, "CVE-2017-0145": 9.3},
    )
    assert findings  # non-empty
    # SMB with EternalBlue CVEs must outrank SSH on the same host.
    smb = next(f for f in findings if ":445/" in f.service_summary)
    ssh = next(f for f in findings if ":22/" in f.service_summary)
    assert smb.risk.composite > ssh.risk.composite
    assert findings.index(smb) < findings.index(ssh)


def test_every_finding_has_a_reasoning_chain(analyst):
    findings = analyst.analyze_nmap_xml(NMAP_XML_FIXTURE)
    assert findings
    for f in findings:
        assert f.reasoning_chain, f"{f.finding_id} has empty reasoning chain"
        # Reasoning must mention port, ATT&CK or asset, score, and rank.
        joined = " | ".join(f.reasoning_chain)
        assert "observed open port" in joined
        assert "risk score derived" in joined
        assert "ranked" in joined and "/" in joined  # "ranked N/M"


def test_asset_profile_shifts_ranking(analyst):
    high_crit_for_ssh = {
        "10.50.0.10": AssetProfile(address="10.50.0.10", criticality=0.99, role="kdc"),
        "10.50.0.20": AssetProfile(address="10.50.0.20", criticality=0.05, role="dmz-stub"),
    }
    findings = analyst.analyze_nmap_xml(
        NMAP_XML_FIXTURE, asset_profiles=high_crit_for_ssh
    )
    http = next(f for f in findings if ":80/" in f.service_summary)
    ssh = next(f for f in findings if ":22/" in f.service_summary)
    # Once SSH host is mission-critical and HTTP host is sandbox, SSH must
    # outrank HTTP (despite HTTP's higher service-class exploitability prior).
    assert ssh.risk.composite > http.risk.composite


def test_analyst_handles_empty_xml(analyst):
    assert analyst.analyze_nmap_xml("") == []
    assert analyst.analyze_nmap_xml(EMPTY_REPORT) == []


def test_operator_summary_is_human_readable(analyst):
    findings = analyst.analyze_nmap_xml(NMAP_XML_FIXTURE)
    top = findings[0]
    assert top.operator_summary
    assert top.asset_address in top.operator_summary
    # Should not be a JSON blob.
    assert not top.operator_summary.startswith("{")


def test_asset_profile_validates_criticality_range():
    with pytest.raises(ValueError):
        AssetProfile(address="x", criticality=1.5)
    with pytest.raises(ValueError):
        AssetProfile(address="x", criticality=-0.1)


def test_finding_ids_are_unique(analyst):
    findings = analyst.analyze_nmap_xml(NMAP_XML_FIXTURE)
    ids = [f.finding_id for f in findings]
    assert len(set(ids)) == len(ids)


def test_rank_position_appended_to_reasoning_chain(analyst):
    findings = analyst.analyze_nmap_xml(NMAP_XML_FIXTURE)
    for idx, f in enumerate(findings, start=1):
        last = f.reasoning_chain[-1]
        assert last.startswith(f"ranked {idx}/")
