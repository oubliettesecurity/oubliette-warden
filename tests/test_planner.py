"""Tests for the Project Management agent (Planner)."""

from __future__ import annotations

import sys
from itertools import count
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.planner.planner import (  # noqa: E402
    Edge,
    IntentKind,
    Planner,
    TaskGraph,
)


@pytest.fixture
def planner():
    counters = {}
    def _id(prefix):
        counters[prefix] = counters.get(prefix, count(1))
        return f"{prefix}-{next(counters[prefix]):03d}"
    return Planner(id_factory=_id)


def test_classify_enumerate(planner):
    assert planner.classify("enumerate hosts on 10.50.0.0/24") == IntentKind.ENUMERATE
    assert planner.classify("scan the subnet") == IntentKind.ENUMERATE
    assert planner.classify("discover assets in this range") == IntentKind.ENUMERATE


def test_classify_service_version(planner):
    assert planner.classify("identify service versions") == IntentKind.SERVICE_VERSION
    assert planner.classify("get the banner of every host") == IntentKind.SERVICE_VERSION


def test_classify_vuln_scan(planner):
    assert planner.classify("run a vuln scan against the dmz") == IntentKind.VULN_SCAN
    assert planner.classify("identify vulnerabilities in subnet") == IntentKind.VULN_SCAN


def test_classify_unknown(planner):
    assert planner.classify("make me a sandwich") == IntentKind.UNKNOWN


def test_extract_scope_from_cidr(planner):
    scope = planner.extract_scope("enumerate hosts on 10.50.0.0/24")
    assert "10.50.0.0/24" in scope


def test_extract_scope_from_explicit(planner):
    scope = planner.extract_scope("anything", explicit_scope=["host01.example", "10.0.0.0/8"])
    assert scope == ["host01.example", "10.0.0.0/8"]


def test_plan_enumerate_emits_one_node(planner):
    g = planner.plan("enumerate hosts on 10.50.0.0/24")
    assert len(g.nodes) == 1
    assert g.nodes[0].metadata["phase"] == "recon"
    assert "10.50.0.0/24" in g.nodes[0].target_scope


def test_plan_service_version_emits_two_nodes(planner):
    g = planner.plan("identify service versions on 10.50.0.0/24")
    phases = [n.metadata["phase"] for n in g.nodes]
    assert "recon" in phases
    assert "service_version" in phases
    assert len(g.edges) == 1


def test_plan_vuln_scan_emits_four_nodes(planner):
    g = planner.plan("vuln scan against 10.50.0.0/24")
    phases = [n.metadata["phase"] for n in g.nodes]
    assert phases == ["recon", "service_version", "vuln_enum", "research"]
    assert len(g.edges) == 3


def test_topological_order_is_deterministic(planner):
    g = planner.plan("vuln scan against 10.50.0.0/24")
    order = g.topological_order()
    phase_order = [n.metadata["phase"] for n in order]
    assert phase_order == ["recon", "service_version", "vuln_enum", "research"]


def test_plan_raises_when_no_scope(planner):
    with pytest.raises(ValueError, match="target scope"):
        planner.plan("just look around")


def test_plan_default_operator_approval_is_false(planner):
    g = planner.plan("enumerate hosts on 10.50.0.0/24")
    assert all(not n.operator_approved for n in g.nodes)


def test_plan_attck_tags_present(planner):
    g = planner.plan("vuln scan against 10.50.0.0/24")
    for n in g.nodes:
        if n.metadata["phase"] != "research":
            assert n.attck_technique_ids, f"node {n.task_id} missing ATT&CK tags"


def test_taskgraph_detects_cycle():
    from oubliette_warden.agents.codegen.base import Task as CodegenTask
    a = CodegenTask(task_id="a", intent="", target_scope=["10.0.0.1"])
    b = CodegenTask(task_id="b", intent="", target_scope=["10.0.0.1"])
    g = TaskGraph(intent="", target_scope=["10.0.0.1"], nodes=[a, b], edges=[Edge("a", "b"), Edge("b", "a")])
    with pytest.raises(ValueError, match="cycle"):
        g.topological_order()
