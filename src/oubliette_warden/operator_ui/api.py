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

Authentication (CRIT-2 fix): ``POST /reviews/{id}/decide`` is a
safety-relevant write — it clears a pending safety-gate escalation. It is
gated by a shared-secret API key, checked with a constant-time compare.
Callers authenticate with ``Authorization: Bearer <token>`` or
``X-API-Key: <token>``; the token maps to an authoritative operator id via
the ``api_keys`` mapping passed to ``create_app`` (or the
``OUBLIETTE_WARDEN_API_KEYS`` env var, formatted as
``"token1:operator1,token2:operator2"``). The request body's
``operator_id`` field is accepted for backward compatibility but is
NON-AUTHORITATIVE and never used to attribute a decision — the operator
identity always comes from the authenticated token. If no keys are
configured, the endpoint fails closed (401) rather than trusting the caller.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from .review_queue import ReviewQueue, ReviewQueueError, ReviewVerdict

API_KEYS_ENV_VAR = "OUBLIETTE_WARDEN_API_KEYS"


try:  # FastAPI is optional at import time; raise only on use.
    from pydantic import BaseModel

    class DecideBody(BaseModel):
        verdict: str  # "approve" | "reject" | "modify"
        # Non-authoritative label only — the authenticated principal (from the
        # API key) is always used for authorization/attribution. Kept for
        # backward-compatible request bodies; never trusted for auth.
        operator_id: str = ""
        rationale: str = ""
        modified_payload: dict[str, Any] | None = None
except ImportError:  # pragma: no cover
    DecideBody = None


def _parse_api_keys(raw: str) -> dict[str, str]:
    """Parse ``"token1:operator1,token2:operator2"`` into a token->operator map."""
    keys: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        token, _, operator_id = pair.partition(":")
        token = token.strip()
        operator_id = operator_id.strip()
        if token and operator_id:
            keys[token] = operator_id
    return keys


def create_app(queue: ReviewQueue, api_keys: dict[str, str] | None = None):
    """Build a FastAPI app bound to the given queue.

    Lazy import keeps the module importable in environments without FastAPI
    (e.g. the airgap dev workstation before deps are installed).

    ``api_keys`` maps a shared-secret token to the operator id it
    authenticates as. If omitted, it is loaded from the
    ``OUBLIETTE_WARDEN_API_KEYS`` env var. If no keys are configured either
    way, the decide endpoint fails closed for every request.
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
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

    keys = (
        dict(api_keys)
        if api_keys is not None
        else _parse_api_keys(os.environ.get(API_KEYS_ENV_VAR, ""))
    )

    def authenticate_operator(
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> str:
        """Fail-closed bearer/API-key check. Returns the authenticated operator id."""
        token = None
        if authorization:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer" and value:
                token = value.strip()
        if token is None and x_api_key:
            token = x_api_key.strip()
        if not token:
            raise HTTPException(status_code=401, detail="missing API credentials")
        for candidate_token, operator_id in keys.items():
            if hmac.compare_digest(candidate_token, token):
                return operator_id
        raise HTTPException(status_code=401, detail="invalid API credentials")

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
    def decide_review(
        review_id: str,
        body: DecideBody,
        operator_id: str = Depends(authenticate_operator),
    ) -> dict[str, Any]:
        try:
            verdict = ReviewVerdict(body.verdict.lower())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            decision = queue.decide(
                review_id,
                verdict=verdict,
                # Authoritative identity comes from the authenticated caller,
                # never from the request body (body.operator_id is a
                # non-authoritative label only — see module docstring).
                operator_id=operator_id,
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
