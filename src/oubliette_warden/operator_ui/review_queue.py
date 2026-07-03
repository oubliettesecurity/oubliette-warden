"""In-memory review queue + audit log for the Operator UI.

The acceptance criteria for §2 Objective 6 are concrete:

  - operator views the live task queue
  - operator can approve / reject / modify any pending action
  - decisions are persisted with operator identity and timestamp
  - complete workflow is replayable from the audit log without
    re-executing tools

Phase I uses an in-memory store. Persistence migrates to SQLite/Postgres in
Phase II hardening. The ``audit_log`` accessor returns the full immutable
trail that drives replay.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ReviewVerdict(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    MODIFY = "modify"


@dataclass(frozen=True)
class PendingReview:
    """A unit of work awaiting operator review.

    The ``proposing_agent`` and ``reasoning_chain`` fields are what the React
    dashboard renders so the operator can read *why* before deciding.
    """

    review_id: str
    proposing_agent: str
    action_kind: str
    summary: str
    reasoning_chain: list[str]
    proposed_at: str
    payload: dict[str, Any] = field(default_factory=dict)
    dedup_key: str | None = None


@dataclass(frozen=True)
class ReviewDecision:
    review_id: str
    verdict: ReviewVerdict
    operator_id: str
    decided_at: str
    rationale: str = ""
    modified_payload: dict[str, Any] | None = None


class ReviewQueueError(RuntimeError):
    """Raised on contract violations (unknown id, double-decide, etc.)."""


class ReviewQueue:
    """Thread-safe queue + audit log.

    The same instance is shared between the FastAPI app and downstream
    agents that enqueue work for review.
    """

    def __init__(self, *, clock=None, id_factory=None) -> None:
        self._lock = threading.RLock()
        self._pending: dict[str, PendingReview] = {}
        self._decisions: dict[str, ReviewDecision] = {}
        self._audit: list[dict[str, Any]] = []
        # review_id -> dedup_key, so a decision can be correlated back to the
        # command that requested review.
        self._keys: dict[str, str] = {}
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self._mint_id = id_factory or (lambda: f"rv-{uuid.uuid4().hex[:8]}")

    # ----- enqueue -----

    def enqueue(
        self,
        *,
        proposing_agent: str,
        action_kind: str,
        summary: str,
        reasoning_chain: list[str],
        payload: dict[str, Any] | None = None,
        dedup_key: str | None = None,
    ) -> PendingReview:
        with self._lock:
            review = PendingReview(
                review_id=self._mint_id(),
                proposing_agent=proposing_agent,
                action_kind=action_kind,
                summary=summary,
                reasoning_chain=list(reasoning_chain),
                proposed_at=self._clock(),
                payload=dict(payload or {}),
                dedup_key=dedup_key,
            )
            self._pending[review.review_id] = review
            if dedup_key is not None:
                self._keys[review.review_id] = dedup_key
            self._audit.append(
                {
                    "kind": "enqueue",
                    "at": review.proposed_at,
                    "review_id": review.review_id,
                    "agent": proposing_agent,
                    "action": action_kind,
                    "summary": summary,
                }
            )
            return review

    # ----- list / read -----

    def list_pending(self) -> list[PendingReview]:
        with self._lock:
            return list(self._pending.values())

    def get(self, review_id: str) -> PendingReview | None:
        with self._lock:
            return self._pending.get(review_id) or self._completed_view(review_id)

    def _completed_view(self, review_id: str) -> PendingReview | None:
        # Allow inspection of completed reviews by replaying audit entries.
        # Returns the PendingReview snapshot stored in audit, if present.
        for entry in self._audit:
            if entry.get("review_id") == review_id and entry.get("kind") == "enqueue":
                # Reconstruct PendingReview from the audit row.
                return PendingReview(
                    review_id=review_id,
                    proposing_agent=entry["agent"],
                    action_kind=entry["action"],
                    summary=entry["summary"],
                    reasoning_chain=[],
                    proposed_at=entry["at"],
                    payload={},
                )
        return None

    # ----- decide -----

    def decide(
        self,
        review_id: str,
        *,
        verdict: ReviewVerdict,
        operator_id: str,
        rationale: str = "",
        modified_payload: dict[str, Any] | None = None,
    ) -> ReviewDecision:
        with self._lock:
            if review_id not in self._pending:
                if review_id in self._decisions:
                    raise ReviewQueueError(
                        f"review {review_id!r} already decided"
                    )
                raise ReviewQueueError(f"unknown review {review_id!r}")
            if not operator_id:
                raise ReviewQueueError("operator_id is required")
            if verdict == ReviewVerdict.MODIFY and modified_payload is None:
                raise ReviewQueueError(
                    "MODIFY verdict requires a modified_payload"
                )
            decision = ReviewDecision(
                review_id=review_id,
                verdict=verdict,
                operator_id=operator_id,
                decided_at=self._clock(),
                rationale=rationale,
                modified_payload=(
                    dict(modified_payload) if modified_payload is not None else None
                ),
            )
            self._decisions[review_id] = decision
            self._pending.pop(review_id, None)
            self._audit.append(
                {
                    "kind": "decide",
                    "at": decision.decided_at,
                    "review_id": review_id,
                    "verdict": verdict.value,
                    "operator_id": operator_id,
                    "rationale": rationale,
                    "modified": bool(modified_payload),
                }
            )
            return decision

    # ----- approval lookup -----

    def is_key_approved(self, dedup_key: str) -> bool:
        """True if any review carrying ``dedup_key`` was decided APPROVE.

        Lets a caller (e.g. a CommandAdapter) correlate an operator's APPROVE
        back to the specific command that was escalated, so execution only
        proceeds once that command has been explicitly cleared.
        """
        with self._lock:
            for review_id, decision in self._decisions.items():
                if (
                    decision.verdict == ReviewVerdict.APPROVE
                    and self._keys.get(review_id) == dedup_key
                ):
                    return True
            return False

    def has_pending_key(self, dedup_key: str) -> bool:
        """True if a still-pending review carries ``dedup_key``."""
        with self._lock:
            return any(r.dedup_key == dedup_key for r in self._pending.values())

    # ----- audit / replay -----

    def audit_log(self) -> list[dict[str, Any]]:
        """Return a deep-copied snapshot of the immutable audit trail."""
        with self._lock:
            return [dict(e) for e in self._audit]

    def replay(self) -> Iterator[dict[str, Any]]:
        """Yield audit entries in order. Replay reproduces the workflow.

        The contract: a consumer iterating ``replay()`` sees the same sequence
        of enqueue/decide entries that occurred originally, without re-running
        any tools. Phase II will persist the audit log; the iterator shape is
        stable across that change.
        """
        yield from self.audit_log()
