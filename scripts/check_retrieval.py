"""Quick retrieval probe — verify Qdrant returns the right CVE for a query.

Faster than the full eval for confirming retrieval health. Embeds a query
(with the query prefix) and prints the top-k hits with scores.

Usage:
    python scripts/check_retrieval.py "Java logging library RCE via JNDI lookup"
    python scripts/check_retrieval.py --k 5 "Exchange server-side request forgery"

A healthy index returns the expected CVE at rank 1 with a clearly higher
score than the rest. If the right CVE isn't in the top-k, retrieval (not
the LLM) is the bottleneck.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.ollama_backend import (  # noqa: E402
    OLLAMA_DEFAULT_EMBED_MODEL,
    OllamaEmbedder,
    OllamaTransport,
)
from oubliette_warden.agents.research.qdrant_backend import (  # noqa: E402
    DEFAULT_COLLECTION,
    QDRANT_DEFAULT_URL,
    QdrantTransport,
    _embed_query,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("query", nargs="+", help="the search query text")
    p.add_argument("--k", type=int, default=5)
    p.add_argument("--qdrant", default=QDRANT_DEFAULT_URL)
    p.add_argument("--ollama", default="http://127.0.0.1:11434")
    p.add_argument("--collection", default=DEFAULT_COLLECTION)
    p.add_argument("--embed-model", default=OLLAMA_DEFAULT_EMBED_MODEL)
    args = p.parse_args(argv)

    query = " ".join(args.query)
    embedder = OllamaEmbedder(
        model=args.embed_model, transport=OllamaTransport(base_url=args.ollama)
    )
    vector = _embed_query(embedder, query)

    transport = QdrantTransport(base_url=args.qdrant)
    result = transport.post(
        f"/collections/{args.collection}/points/search",
        {"vector": vector, "limit": args.k, "with_payload": True},
    )
    hits = result.get("result", []) or []

    print(f"query: {query!r}")
    print(f"top {len(hits)} hits from {args.collection}:")
    print("-" * 72)
    for i, hit in enumerate(hits, start=1):
        payload = hit.get("payload") or {}
        cve = payload.get("cve_id", "?")
        score = hit.get("score", 0.0)
        desc = (payload.get("description", "") or "")[:80]
        print(f"  {i}. {cve:<18} score={score:.4f}  {desc}")
    if not hits:
        print("  (no hits — is the collection seeded? is Qdrant running?)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
