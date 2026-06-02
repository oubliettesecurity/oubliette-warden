"""Operator UI — §2 Objective 6 (cross-cutting human-on-the-loop interface).

Phase I deliverable: the backend HTTP contract that the React review
dashboard (lifted from ``oubliette-dungeon``) targets. The frontend lift
itself is a separate task once a development workstation is available; the
contract is testable today and pinned by the suite below.

Public surface:

  - ``review_queue.ReviewQueue`` — in-memory review queue (audit-log-bound)
  - ``api.create_app`` — FastAPI factory if FastAPI is importable; raises
    a clear error otherwise so the import never silently no-ops
"""

from .review_queue import (
    PendingReview,
    ReviewDecision,
    ReviewQueue,
    ReviewVerdict,
)

__all__ = [
    "PendingReview",
    "ReviewDecision",
    "ReviewQueue",
    "ReviewVerdict",
]
