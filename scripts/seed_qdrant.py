"""Seed the Oubliette Warden Qdrant collection from a compacted NVD JSONL corpus.

Pre-requisites:
  1. Run ``scripts/ingest_nvd.py fetch ...`` to populate the cache.
  2. Run ``scripts/ingest_nvd.py compact --out data/nvd_corpus.jsonl``.
  3. Start Qdrant (via the project's docker compose).
  4. Pull an Ollama embedding model:  ``ollama pull nomic-embed-text``.

Then:

  python scripts/seed_qdrant.py --jsonl data/nvd_corpus.jsonl

CPU embedding for ~10K records on a laptop takes single-digit minutes.
For the full ~250K NVD corpus, consider pre-filtering to KEV + relevant
years, or running overnight.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Iterator

# Allow `python scripts/seed_qdrant.py` from the repo root.
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
    ensure_collection,
    upsert_records,
)
from oubliette_warden.agents.research.researcher import CorpusRecord  # noqa: E402

logger = logging.getLogger("seed_qdrant")


def iter_corpus(path: Path) -> Iterator[CorpusRecord]:
    """Yield CorpusRecord per line of the compacted NVD JSONL file."""
    lines_seen = 0
    rejected_no_id = 0
    # ``utf-8-sig`` strips a BOM on the first line if present. Windows
    # PowerShell 5.1's `Out-File -Encoding utf8` writes a BOM, which
    # would otherwise turn line 1 into a json.loads failure.
    with path.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lines_seen += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("skipping malformed JSONL line %d: %s", lines_seen, e)
                continue
            # ingest_nvd.py emits records under "id"; tolerate "cve_id" too.
            cve_id = row.get("id") or row.get("cve_id")
            if not cve_id:
                rejected_no_id += 1
                continue
            description = row.get("description", "") or ""
            cvss = row.get("cvss") or {}
            # ingest_nvd emits cvss.baseSeverity; tolerate the legacy
            # ``severity`` key for forward-compat.
            cvss_severity = None
            if isinstance(cvss, dict):
                cvss_severity = cvss.get("baseSeverity") or cvss.get("severity")
            # ingest_nvd emits "references"; tolerate "refs" for forward-compat.
            references = row.get("references") or row.get("refs") or []
            yield CorpusRecord(
                cve_id=str(cve_id),
                description=str(description),
                cvss_severity=cvss_severity,
                references=[str(u) for u in references if u],
            )
    logger.info(
        "iter_corpus: %d JSONL lines seen, %d rejected for missing id",
        lines_seen,
        rejected_no_id,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--jsonl",
        default="data/nvd_corpus.jsonl",
        help="path to compacted NVD JSONL produced by ingest_nvd.py compact",
    )
    parser.add_argument(
        "--qdrant",
        default=QDRANT_DEFAULT_URL,
        help="Qdrant base URL (default: http://127.0.0.1:6333)",
    )
    parser.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
        help="Qdrant collection name (default: nvd_corpus)",
    )
    parser.add_argument(
        "--ollama",
        default="http://127.0.0.1:11434",
        help="Ollama base URL (default: http://127.0.0.1:11434)",
    )
    parser.add_argument(
        "--embed-model",
        default=OLLAMA_DEFAULT_EMBED_MODEL,
        help=f"Ollama embedding model (default: {OLLAMA_DEFAULT_EMBED_MODEL})",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="cap the number of records (0 = no cap; useful for smoke tests)",
    )
    parser.add_argument(
        "--start-at", type=int, default=0,
        help=(
            "skip the first N corpus lines and resume (point IDs continue "
            "from N+1). Use after a crash to avoid re-embedding what's "
            "already in Qdrant — e.g. --start-at 16500."
        ),
    )
    parser.add_argument(
        "--recreate", action="store_true",
        help="drop the collection before seeding (destructive)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=64,
        help="upsert batch size (default: 64)",
    )
    args = parser.parse_args(argv)

    if args.start_at and args.recreate:
        parser.error("--start-at and --recreate are mutually exclusive")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_file():
        logger.error("JSONL not found: %s", jsonl_path)
        logger.error("Run: python scripts/ingest_nvd.py compact --out %s", jsonl_path)
        return 1

    ollama_transport = OllamaTransport(base_url=args.ollama)
    embedder = OllamaEmbedder(model=args.embed_model, transport=ollama_transport)

    # Probe the embedder to discover the vector size up front.
    probe_vector = embedder.embed("probe")
    vector_size = len(probe_vector)
    logger.info("embedding model %s emits %d-dim vectors", args.embed_model, vector_size)

    qdrant_transport = QdrantTransport(base_url=args.qdrant)
    ensure_collection(
        qdrant_transport,
        collection=args.collection,
        vector_size=vector_size,
        recreate=args.recreate,
    )
    logger.info("collection ready: %s", args.collection)

    def _bounded() -> Iterator[CorpusRecord]:
        for i, rec in enumerate(iter_corpus(jsonl_path), start=1):
            if i <= args.start_at:
                continue  # already seeded in a prior run
            if args.limit and i > args.limit:
                return
            if i % 500 == 0:
                logger.info("...embedded %d records", i)
            yield rec

    if args.start_at:
        logger.info("resuming: skipping first %d corpus lines", args.start_at)

    written = upsert_records(
        qdrant_transport,
        embedder,
        _bounded(),
        collection=args.collection,
        batch_size=args.batch_size,
        start_index=args.start_at,
    )
    logger.info("seeded %d points into %s (resume offset %d)", written, args.collection, args.start_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
