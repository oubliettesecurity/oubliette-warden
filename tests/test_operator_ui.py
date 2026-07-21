"""Tests for the Operator UI scaffold (§2 Objective 6).

Two layers:

  1. ReviewQueue contract — exercised directly, no FastAPI needed.
  2. HTTP layer — only runs if FastAPI + httpx are importable.
"""

from __future__ import annotations

import sys
from itertools import count
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.operator_ui.review_queue import (  # noqa: E402
    ReviewQueue,
    ReviewQueueError,
    ReviewVerdict,
)


@pytest.fixture
def queue():
    clock_seq = iter([
        "2026-05-13T12:00:00+00:00",
        "2026-05-13T12:01:00+00:00",
        "2026-05-13T12:02:00+00:00",
        "2026-05-13T12:03:00+00:00",
        "2026-05-13T12:04:00+00:00",
        "2026-05-13T12:05:00+00:00",
    ])
    counter = count(1)
    return ReviewQueue(
        clock=lambda: next(clock_seq),
        id_factory=lambda: f"rv-{next(counter):03d}",
    )


# ---------- enqueue / list / get ----------


def test_enqueue_creates_pending_review(queue):
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="emit_task_graph",
        summary="enumerate hosts on 10.50.0.0/24",
        reasoning_chain=["intent classified ENUMERATE", "scope=10.50.0.0/24"],
    )
    assert rv.review_id == "rv-001"
    assert rv.proposing_agent == "planner"
    assert rv.reasoning_chain[0].startswith("intent classified")
    assert queue.list_pending() == [rv]


def test_get_unknown_review_returns_none(queue):
    assert queue.get("rv-does-not-exist") is None


# ---------- decide ----------


def test_decide_approve_clears_pending_and_appends_audit(queue):
    rv = queue.enqueue(
        proposing_agent="codegen",
        action_kind="emit_nmap_command",
        summary="nmap -sV -sC 10.50.0.10",
        reasoning_chain=["safety pipeline APPROVED"],
    )
    decision = queue.decide(
        rv.review_id,
        verdict=ReviewVerdict.APPROVE,
        operator_id="op-alice",
        rationale="phase 1 enumeration in caldera range",
    )
    assert decision.verdict == ReviewVerdict.APPROVE
    assert decision.operator_id == "op-alice"
    assert queue.list_pending() == []
    log = queue.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == ["enqueue", "decide"]


def test_decide_reject_records_rationale(queue):
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="emit_task_graph",
        summary="out of scope target",
        reasoning_chain=[],
    )
    decision = queue.decide(
        rv.review_id,
        verdict=ReviewVerdict.REJECT,
        operator_id="op-bob",
        rationale="target 10.99.0.0/24 outside authorized range",
    )
    assert decision.verdict == ReviewVerdict.REJECT
    assert "outside authorized range" in decision.rationale


def test_decide_modify_requires_payload(queue):
    rv = queue.enqueue(
        proposing_agent="codegen",
        action_kind="emit_nmap_command",
        summary="too wide",
        reasoning_chain=[],
    )
    with pytest.raises(ReviewQueueError):
        queue.decide(rv.review_id, verdict=ReviewVerdict.MODIFY, operator_id="op-cara")


def test_decide_modify_carries_modified_payload(queue):
    rv = queue.enqueue(
        proposing_agent="codegen",
        action_kind="emit_nmap_command",
        summary="too wide",
        reasoning_chain=[],
    )
    decision = queue.decide(
        rv.review_id,
        verdict=ReviewVerdict.MODIFY,
        operator_id="op-cara",
        modified_payload={"target": "10.50.0.10"},
    )
    assert decision.modified_payload == {"target": "10.50.0.10"}


def test_decide_unknown_review_raises(queue):
    with pytest.raises(ReviewQueueError):
        queue.decide("rv-missing", verdict=ReviewVerdict.APPROVE, operator_id="op-x")


def test_decide_twice_raises(queue):
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="x",
        summary="y",
        reasoning_chain=[],
    )
    queue.decide(rv.review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-a")
    with pytest.raises(ReviewQueueError):
        queue.decide(rv.review_id, verdict=ReviewVerdict.REJECT, operator_id="op-a")


def test_decide_requires_operator_id(queue):
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="x",
        summary="y",
        reasoning_chain=[],
    )
    with pytest.raises(ReviewQueueError):
        queue.decide(rv.review_id, verdict=ReviewVerdict.APPROVE, operator_id="")


# ---------- audit log / replay ----------


def test_replay_yields_full_workflow_in_order(queue):
    a = queue.enqueue(
        proposing_agent="planner",
        action_kind="plan",
        summary="recon",
        reasoning_chain=[],
    )
    queue.decide(a.review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-a")
    b = queue.enqueue(
        proposing_agent="codegen",
        action_kind="nmap",
        summary="scan",
        reasoning_chain=[],
    )
    queue.decide(b.review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-a")
    log = list(queue.replay())
    assert [e["kind"] for e in log] == ["enqueue", "decide", "enqueue", "decide"]


def test_audit_log_is_a_snapshot(queue):
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="plan",
        summary="recon",
        reasoning_chain=[],
    )
    log1 = queue.audit_log()
    queue.decide(rv.review_id, verdict=ReviewVerdict.APPROVE, operator_id="op-a")
    log2 = queue.audit_log()
    # log1 should NOT have grown after the decide call.
    assert len(log1) == 1
    assert len(log2) == 2


# ---------- HTTP layer (skipped if FastAPI not installed) ----------


def test_http_layer_smoke():
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")
    from oubliette_warden.operator_ui.api import create_app

    queue = ReviewQueue()
    app = create_app(queue, api_keys={"secret-token": "op-alice"})
    client = TestClient(app)

    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="plan",
        summary="recon",
        reasoning_chain=["scope=10.50.0.0/24"],
    )

    r = client.get("/reviews")
    assert r.status_code == 200
    assert any(item["review_id"] == rv.review_id for item in r.json())

    r = client.get(f"/reviews/{rv.review_id}")
    assert r.status_code == 200
    assert r.json()["proposing_agent"] == "planner"

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"Authorization": "Bearer secret-token"},
        json={"verdict": "approve", "operator_id": "op-alice", "rationale": "ok"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "approve"
    assert body["operator_id"] == "op-alice"

    # Second decide on same id should conflict.
    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"Authorization": "Bearer secret-token"},
        json={"verdict": "reject", "operator_id": "op-alice"},
    )
    assert r.status_code == 409

    r = client.get("/audit")
    assert r.status_code == 200
    assert len(r.json()) == 2


# ---------- CRIT-2: /decide authentication (fail-closed) ----------


def _auth_client():
    """A TestClient + a pending review, wired with a single valid API key."""
    from fastapi.testclient import TestClient

    from oubliette_warden.operator_ui.api import create_app

    queue = ReviewQueue()
    app = create_app(queue, api_keys={"secret-token": "op-alice"})
    client = TestClient(app)
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="plan",
        summary="recon",
        reasoning_chain=[],
    )
    return client, rv


def test_decide_without_credentials_is_rejected():
    try:
        client, rv = _auth_client()
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        json={"verdict": "approve", "operator_id": "op-alice"},
    )
    assert r.status_code == 401


def test_decide_with_wrong_token_is_rejected():
    try:
        client, rv = _auth_client()
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"Authorization": "Bearer wrong-token"},
        json={"verdict": "approve", "operator_id": "op-alice"},
    )
    assert r.status_code == 401


def test_decide_with_valid_x_api_key_header_succeeds():
    try:
        client, rv = _auth_client()
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"X-API-Key": "secret-token"},
        json={"verdict": "approve", "operator_id": "op-alice"},
    )
    assert r.status_code == 200
    assert r.json()["operator_id"] == "op-alice"


def test_decide_ignores_forged_operator_id_in_body():
    """A caller authenticated as op-alice cannot impersonate another operator
    by putting a different operator_id in the request body."""
    try:
        client, rv = _auth_client()
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"Authorization": "Bearer secret-token"},
        json={"verdict": "approve", "operator_id": "op-mallory"},
    )
    assert r.status_code == 200
    assert r.json()["operator_id"] == "op-alice"


def test_decide_fails_closed_when_no_api_keys_configured():
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("FastAPI/httpx not installed in this environment")
    from oubliette_warden.operator_ui.api import create_app

    queue = ReviewQueue()
    app = create_app(queue, api_keys={})  # explicitly no keys configured
    client = TestClient(app)
    rv = queue.enqueue(
        proposing_agent="planner",
        action_kind="plan",
        summary="recon",
        reasoning_chain=[],
    )

    r = client.post(
        f"/reviews/{rv.review_id}/decide",
        headers={"Authorization": "Bearer anything-at-all"},
        json={"verdict": "approve", "operator_id": "op-alice"},
    )
    assert r.status_code == 401
