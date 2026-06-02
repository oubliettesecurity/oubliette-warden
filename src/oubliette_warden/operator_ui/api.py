"""FastAPI HTTP contract for the Operator UI.

Three resources (sufficient for the React review dashboard from
``oubliette-dungeon`` to drive):

  GET  /reviews              list pending reviews
  GET  /reviews/{id}         get one review
  POST /reviews/{id}/decide  approve / reject / modify
  GET  /audit                full immutable audit log (for replay)

This module is import-safe even when FastAPI is not installed: it only
imports FastAPI inside ``create_app``. The unit tests exercise the
``ReviewQueue`` directly; an HTTP smoke test runs only if ``httpx`` and
``fastapi`` are present.
"""

from __future__ import annotations

from typing import Any

from .review_queue import ReviewQueue, ReviewQueueError, ReviewVerdict


try:  # FastAPI is optional at import time; raise only on use.
    from pydantic import BaseModel

    class DecideBody(BaseModel):
        verdict: str  # "approve" | "reject" | "modify"
        operator_id: str
        rationale: str = ""
        modified_payload: dict[str, Any] | None = None
except ImportError:  # pragma: no cover
    DecideBody = None  # type: ignore[assignment, misc]


def create_app(queue: ReviewQueue):
    """Build a FastAPI app bound to the given queue.

    Lazy import keeps the module importable in environments without FastAPI
    (e.g. the airgap dev workstation before deps are installed).
    """
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as exc:  # pragma: no cover - exercised on bare env
        raise RuntimeError(
            "FastAPI required for the Operator UI HTTP layer. "
            "Install with: pip install fastapi"
        ) from exc
    if DecideBody is None:  # pragma: no cover
        raise RuntimeError(
            "pydantic required for the Operator UI HTTP layer. "
            "Install with: pip install pydantic"
        )

    app = FastAPI(title="Oubliette Warden Operator UI", version="0.1.0")

    @app.get("/reviews")
    def list_reviews() -> list[dict[str, Any]]:
        return [_serialize(r) for r in queue.list_pending()]

    @app.get("/reviews/{review_id}")
    def get_review(review_id: str) -> dict[str, Any]:
        rv = queue.get(review_id)
        if rv is None:
            raise HTTPException(status_code=404, detail="review not found")
        return _serialize(rv)

    @app.post("/reviews/{review_id}/decide")
    def decide_review(review_id: str, body: DecideBody) -> dict[str, Any]:
        try:
            verdict = ReviewVerdict(body.verdict.lower())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            decision = queue.decide(
                review_id,
                verdict=verdict,
                operator_id=body.operator_id,
                rationale=body.rationale,
                modified_payload=body.modified_payload,
            )
        except ReviewQueueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "review_id": decision.review_id,
            "verdict": decision.verdict.value,
            "operator_id": decision.operator_id,
            "decided_at": decision.decided_at,
            "rationale": decision.rationale,
        }

    @app.get("/audit")
    def audit() -> list[dict[str, Any]]:
        return queue.audit_log()

    return app


def _serialize(rv) -> dict[str, Any]:
    return {
        "review_id": rv.review_id,
        "proposing_agent": rv.proposing_agent,
        "action_kind": rv.action_kind,
        "summary": rv.summary,
        "reasoning_chain": list(rv.reasoning_chain),
        "proposed_at": rv.proposed_at,
        "payload": dict(rv.payload),
    }
