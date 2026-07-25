"""Unit tests for the ExecutionSession runner (CRIT-1 completion).

CRIT-1 wired plan_consistency into the safety gate and made it fail closed when
no plan context is set, but nothing in the real command-execution path actually
*set* an adapter's ``_gate_context`` — so every real ``execute()`` would DENY as
unattributable. These tests drive a small TaskGraph end-to-end through the real
path (``adapter.execute()`` -> ``_gate_or_raise`` -> ``evaluate(context=...)``)
via a thin ExecutionSession that owns the plan + completed-task set and threads
a ``GateContext`` into each adapter before its command runs.

The MSF auxiliary adapter is used because its RPC client is injectable, so
``execute()`` can complete end-to-end in a unit test (nmap needs a real binary).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.codegen.base import (
    ExecutionEnv,
    Task,
)
from oubliette_warden.agents.codegen.msf_adapter import (
    MSFAuxAdapter,
    MSFPolicyError,
)
from oubliette_warden.agents.codegen.runner import ExecutionSession
from oubliette_warden.agents.codegen.safety_gate import Verdict
from oubliette_warden.agents.planner.planner import Edge, TaskGraph
from oubliette_warden.operator_ui.review_queue import ReviewQueue, ReviewVerdict

SCOPE = ["10.0.0.1"]
# The portscan/tcp module the adapter emits for a keyword-free intent tags these
# techniques; the plan must declare them or plan_consistency ESCALATEs on
# "technique beyond plan".
PORTSCAN_TECH = ["T1595.001", "T1018"]


class _FakeMSFClient:
    """Minimal injectable msfrpcd client so execute() completes offline."""

    def module_info(self, module):  # pragma: no cover - not exercised
        return {}

    def module_run(self, module, options):
        return {"rows": [{"host": "10.0.0.1", "info": "445/tcp open"}], "task_id": ""}


def _msf_task(task_id: str, *, approved: bool) -> Task:
    # metadata has no "phase" -> plan_consistency's adapter/phase soft check is
    # skipped, isolating the attributability/order/approval checks under test.
    return Task(
        task_id=task_id,
        intent="scan hosts",  # keyword-free -> portscan/tcp module
        target_scope=SCOPE,
        attck_technique_ids=list(PORTSCAN_TECH),
        operator_approved=approved,
        metadata={},
    )


def _single_plan(*, approved: bool) -> TaskGraph:
    return TaskGraph(
        intent="t",
        target_scope=SCOPE,
        nodes=[_msf_task("task-a", approved=approved)],
        edges=[],
    )


def _two_plan(*, approved: bool) -> TaskGraph:
    return TaskGraph(
        intent="t",
        target_scope=SCOPE,
        nodes=[
            _msf_task("task-a", approved=approved),
            _msf_task("task-b", approved=approved),
        ],
        edges=[Edge(before="task-a", after="task-b")],
    )


def _preapprove(rq: ReviewQueue, adapter: MSFAuxAdapter, plan: TaskGraph) -> None:
    """Model operator sign-off: pre-approve each command's dedup key so the
    CRIT-3 llm_judge ESCALATE is cleared and execute() actually runs."""
    for node in plan.nodes:
        cmd = adapter.plan(node)
        key = adapter._command_key(cmd, ExecutionEnv.CALDERA_ONLY)
        rv = rq.enqueue(
            proposing_agent="test",
            action_kind="execute",
            summary="",
            reasoning_chain=[],
            dedup_key=key,
        )
        rq.decide(rv.review_id, verdict=ReviewVerdict.APPROVE, operator_id="op")


# ---------- (a) in-plan, approved, in-order task executes; plan_consistency APPROVEs ----------


def test_session_drives_plan_consistency_and_executes_in_order():
    rq = ReviewQueue()
    adapter = MSFAuxAdapter(client=_FakeMSFClient(), review_queue=rq)
    plan = _two_plan(approved=True)
    _preapprove(rq, adapter, plan)

    session = ExecutionSession(
        plan, ExecutionEnv.CALDERA_ONLY, adapter_for=lambda _t: adapter
    )
    outcomes = session.run()
    by_id = {o.task_id: o for o in outcomes}

    for tid in ("task-a", "task-b"):
        o = by_id[tid]
        assert o.status == "executed", o.error
        assert o.finding is not None
        stages = {s.stage: s.verdict for s in o.decision.stages}
        # plan_consistency ran FIRST and APPROVED at execution time.
        assert o.decision.stages[0].stage == "plan_consistency"
        assert stages["plan_consistency"] == Verdict.APPROVE
        # overall may ESCALATE per CRIT-3, but plan_consistency never DENIED.
        assert stages["plan_consistency"] != Verdict.DENY

    # completed set advanced as tasks finished, in order.
    assert session.completed_task_ids == {"task-a", "task-b"}
    # fail-closed hygiene: context reset to None after the run.
    assert adapter._gate_context is None


# ---------- (b) out-of-order / unapproved task is DENY'd by plan_consistency at runtime ----------


def test_session_denies_unapproved_task_at_runtime():
    """Anchored default: an in-plan task lacking operator approval is DENY'd by
    plan_consistency at execution time (not merely at gate-unit level)."""
    adapter = MSFAuxAdapter(client=_FakeMSFClient())
    plan = _single_plan(approved=False)

    session = ExecutionSession(
        plan, ExecutionEnv.CALDERA_ONLY, adapter_for=lambda _t: adapter
    )
    outcomes = session.run()
    o = outcomes[0]

    assert o.status == "blocked"
    assert o.finding is None
    stages = {s.stage: s.verdict for s in o.decision.stages}
    assert stages["plan_consistency"] == Verdict.DENY
    assert isinstance(o.error, MSFPolicyError)
    assert "human-approved" in str(o.error)
    # a blocked task never counts as finished.
    assert session.completed_task_ids == set()
    assert adapter._gate_context is None


def test_session_denies_out_of_order_task_at_runtime():
    """task-b runs before its predecessor task-a completes (task-a is only
    ESCALATED/blocked, never executed) -> plan_consistency DENIES task-b as
    skip-ahead, at execution time, on the real adapter path."""
    rq = ReviewQueue()  # no pre-approval: task-a will ESCALATE and block
    adapter = MSFAuxAdapter(client=_FakeMSFClient(), review_queue=rq)
    plan = _two_plan(approved=True)

    session = ExecutionSession(
        plan, ExecutionEnv.CALDERA_ONLY, adapter_for=lambda _t: adapter
    )
    outcomes = session.run()
    by_id = {o.task_id: o for o in outcomes}

    # task-a: plan_consistency APPROVED, but the run ESCALATES (llm_judge stub)
    # and blocks pending operator review -> not completed.
    a = by_id["task-a"]
    assert a.status == "blocked"
    assert {s.stage: s.verdict for s in a.decision.stages}["plan_consistency"] == Verdict.APPROVE

    # task-b: predecessor never completed -> plan_consistency DENY (skip-ahead).
    b = by_id["task-b"]
    assert b.status == "blocked"
    assert {s.stage: s.verdict for s in b.decision.stages}["plan_consistency"] == Verdict.DENY
    assert "skip-ahead" in str(b.error)

    assert "task-b" not in session.completed_task_ids


# ---------- (c) a task run with NO context still fails closed ----------


def test_execute_without_session_fails_closed():
    """Using an adapter directly (no ExecutionSession) leaves _gate_context
    unset -> the command is unattributable and DENIED. This is the pre-CRIT-1
    hole: the gate only runs meaningfully once a runner threads the context."""
    adapter = MSFAuxAdapter(client=_FakeMSFClient())
    plan = _single_plan(approved=True)
    cmd = adapter.plan(plan.nodes[0])

    assert adapter._gate_context is None  # nothing set it
    with pytest.raises(MSFPolicyError) as ei:
        adapter.execute(cmd, ExecutionEnv.CALDERA_ONLY)
    assert "unattributable" in str(ei.value)


# ---------- runner skips no-op (handoff) nodes and still advances ordering ----------


def test_session_skips_nodes_without_an_adapter():
    """A node the resolver maps to None (e.g. a research handoff with no command)
    is skipped but still marked completed so downstream ordering holds."""
    rq = ReviewQueue()
    adapter = MSFAuxAdapter(client=_FakeMSFClient(), review_queue=rq)
    plan = _two_plan(approved=True)
    _preapprove(rq, adapter, plan)

    # Route task-a to a real adapter, task-b to None (handoff).
    def _resolver(task):
        return None if task.task_id == "task-b" else adapter

    session = ExecutionSession(plan, ExecutionEnv.CALDERA_ONLY, adapter_for=_resolver)
    outcomes = session.run()
    by_id = {o.task_id: o for o in outcomes}

    assert by_id["task-a"].status == "executed"
    assert by_id["task-b"].status == "skipped"
    assert by_id["task-b"].finding is None
    assert session.completed_task_ids == {"task-a", "task-b"}
