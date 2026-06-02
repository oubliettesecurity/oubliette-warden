"""Shots 6–7 of the screencast — Operator UI server with a seeded review.

Usage:
    python -m oubliette_warden.demo.ui

Then visit http://127.0.0.1:8000/reviews and http://127.0.0.1:8000/audit
in a browser. Pre-seeded with a realistic pending review so the screencast
captures meaningful content without manual setup.
"""

from __future__ import annotations

import sys

from ..operator_ui.api import create_app
from ..operator_ui.review_queue import ReviewQueue


def _seed(queue: ReviewQueue) -> None:
    """Populate a representative pending review for screen capture."""
    queue.enqueue(
        proposing_agent="planner",
        action_kind="emit_task_graph",
        summary="enumerate hosts on 10.50.0.0/24",
        reasoning_chain=[
            "intent classified ENUMERATE",
            "scope extracted: 10.50.0.0/24",
            "ATT&CK techniques T1595.001, T1018 attached",
            "operator approval gate set on every node",
        ],
        payload={"task_count": 1, "techniques": ["T1595.001", "T1018"]},
    )
    queue.enqueue(
        proposing_agent="codegen",
        action_kind="emit_nmap_command",
        summary="nmap -sV -sC --script default -oX - 10.50.0.0/24",
        reasoning_chain=[
            "task recon-001 received from planner",
            "Nmap adapter generated parameterized argv",
            "safety pipeline: pre_filter APPROVE, pattern_detector APPROVE, "
            "rag_guard APPROVE, llm_judge APPROVE, mcp_guard APPROVE",
            "final verdict: APPROVE (CALDERA_ONLY env enforced)",
        ],
        payload={
            "adapter": "nmap",
            "env": "CALDERA_ONLY",
            "expected_runtime_seconds": 300,
        },
    )
    # Closing the loop: one previously-decided review so /audit isn't empty.
    pre_decided = queue.enqueue(
        proposing_agent="analyst",
        action_kind="rank_findings",
        summary="3 findings ranked for 10.50.0.0/24 CALDERA range",
        reasoning_chain=[
            "Nmap XML ingested: 3 open ports",
            "exploitability × criticality × CVSS rubric applied",
            "top: 10.50.0.10:445 microsoft-ds (composite=3.44, CVE-2017-0144)",
        ],
        payload={"finding_count": 3},
    )
    from ..operator_ui.review_queue import ReviewVerdict

    queue.decide(
        pre_decided.review_id,
        verdict=ReviewVerdict.APPROVE,
        operator_id="op-jbradford",
        rationale="ranking aligns with operator expectation; forward to research",
    )


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    host = "127.0.0.1"
    port = 8000
    if args and args[0]:
        # allow `python -m oubliette_warden.demo.ui 9000` to override port
        try:
            port = int(args[0])
        except ValueError:
            print(f"invalid port: {args[0]!r}", file=sys.stderr)
            return 2

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn not installed. Install with: pip install fastapi uvicorn",
            file=sys.stderr,
        )
        return 1

    queue = ReviewQueue()
    _seed(queue)
    app = create_app(queue)
    print(f"Oubliette Warden Operator UI — listening on http://{host}:{port}")
    print(f"  GET  http://{host}:{port}/reviews   — pending reviews")
    print(f"  GET  http://{host}:{port}/audit     — immutable audit log")
    print(f"seeded {len(queue.list_pending())} pending review(s) + 1 decided")
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
