"""
Project Management agent (planner).

Takes a high-level scoping intent (e.g. "enumerate hosts on subnet X and identify
exposed services") and produces an ATT&CK-aligned task graph that downstream
agents — Cyber Analysis, Code Generation & Execution, Vulnerability Research —
can consume.

Phase I planner is rule-based with a clean swap-point for an LLM-driven planner
in Phase II. The rule-based core gives us:

  - Determinism (test reproducibility, audit-trail replay)
  - Zero LLM dependency for the smoke demo
  - A surface area the LLM-driven version can inherit and extend

The planner emits a TaskGraph: a list of Task records with explicit dependency
edges, ATT&CK technique tags, target scope, and operator-approval gates on
every node by default.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from ..codegen.base import Task

CIDR_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")
HOST_TOKEN_RE = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")


class IntentKind(str, Enum):
    ENUMERATE = "enumerate"
    SERVICE_VERSION = "service_version"
    VULN_SCAN = "vuln_scan"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Edge:
    """Directed dependency edge: `before` must complete before `after` starts."""

    before: str
    after: str


@dataclass(frozen=True)
class TaskGraph:
    intent: str
    target_scope: list[str]
    nodes: list[Task]
    edges: list[Edge] = field(default_factory=list)

    def topological_order(self) -> list[Task]:
        by_id = {t.task_id: t for t in self.nodes}
        indegree = {t.task_id: 0 for t in self.nodes}
        succ: dict[str, list[str]] = {t.task_id: [] for t in self.nodes}
        for e in self.edges:
            indegree[e.after] += 1
            succ[e.before].append(e.after)
        ready = [tid for tid, d in indegree.items() if d == 0]
        order: list[Task] = []
        while ready:
            tid = ready.pop(0)
            order.append(by_id[tid])
            for nxt in succ[tid]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
        if len(order) != len(self.nodes):
            raise ValueError("cycle detected in task graph")
        return order


class Planner:
    """Rule-based Phase I planner."""

    def __init__(self, id_factory=None) -> None:
        # Inject a deterministic id factory in tests.
        self._mint_id = id_factory or (lambda prefix: f"{prefix}-{uuid.uuid4().hex[:8]}")

    # ---------- public surface ----------

    def classify(self, intent: str) -> IntentKind:
        i = intent.lower()
        if "vuln" in i or "vulnerab" in i:
            return IntentKind.VULN_SCAN
        if "service" in i or "version" in i or "banner" in i:
            return IntentKind.SERVICE_VERSION
        if "enumer" in i or "scan" in i or "discover" in i or "map" in i:
            return IntentKind.ENUMERATE
        return IntentKind.UNKNOWN

    def extract_scope(self, intent: str, explicit_scope: Iterable[str] | None = None) -> list[str]:
        if explicit_scope:
            return [s.strip() for s in explicit_scope if s.strip()]
        cidrs = CIDR_RE.findall(intent)
        hosts = HOST_TOKEN_RE.findall(intent)
        scope = list(dict.fromkeys(cidrs + hosts))  # preserve order, dedupe
        return scope

    def plan(
        self,
        intent: str,
        explicit_scope: Iterable[str] | None = None,
    ) -> TaskGraph:
        kind = self.classify(intent)
        scope = self.extract_scope(intent, explicit_scope)
        if not scope:
            raise ValueError("planner could not determine target scope from intent")

        nodes: list[Task] = []
        edges: list[Edge] = []

        # 1) Reconnaissance — always first
        recon_id = self._mint_id("recon")
        recon = Task(
            task_id=recon_id,
            intent="enumerate hosts and basic service discovery",
            target_scope=scope,
            attck_technique_ids=["T1595.001", "T1018"],
            operator_approved=False,
            metadata={"phase": "recon", "kind": IntentKind.ENUMERATE.value},
        )
        nodes.append(recon)

        # 2) Service version detection — for service_version and vuln_scan kinds
        if kind in (IntentKind.SERVICE_VERSION, IntentKind.VULN_SCAN):
            sv_id = self._mint_id("svcver")
            sv = Task(
                task_id=sv_id,
                intent="service version and banner detection",
                target_scope=scope,
                attck_technique_ids=["T1046"],
                operator_approved=False,
                metadata={"phase": "service_version"},
            )
            nodes.append(sv)
            edges.append(Edge(before=recon_id, after=sv_id))
            previous_id = sv_id
        else:
            previous_id = recon_id

        # 3) Vuln-script enumeration — only for vuln_scan kind
        if kind == IntentKind.VULN_SCAN:
            vs_id = self._mint_id("vuln")
            vs = Task(
                task_id=vs_id,
                intent="vuln scan",
                target_scope=scope,
                attck_technique_ids=["T1595.002", "T1046"],
                operator_approved=False,
                metadata={"phase": "vuln_enum"},
            )
            nodes.append(vs)
            edges.append(Edge(before=previous_id, after=vs_id))
            previous_id = vs_id

        # 4) Researcher consultation — for vuln_scan only, runs after the
        # vuln-script step has produced candidate CVEs.
        if kind == IntentKind.VULN_SCAN:
            rc_id = self._mint_id("research")
            rc = Task(
                task_id=rc_id,
                intent="research candidate cves discovered upstream",
                target_scope=scope,
                attck_technique_ids=[],
                operator_approved=False,
                metadata={"phase": "research", "consumer": "researcher_agent"},
            )
            nodes.append(rc)
            edges.append(Edge(before=previous_id, after=rc_id))

        return TaskGraph(intent=intent, target_scope=scope, nodes=nodes, edges=edges)
