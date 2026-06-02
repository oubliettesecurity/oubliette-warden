"""Qdrant-backed Retriever for the Vulnerability Research agent.

A small ``urllib`` HTTP client against Qdrant's REST API — sufficient for
Phase I, no runtime dependency added.

The retriever expects the collection to be pre-seeded by ``seed_qdrant``
(or the equivalent operator-side script). Each point's payload carries
the CVE id, description, CVSS severity, and reference URLs so the
``Retriever`` Protocol surface can reconstruct ``CorpusRecord`` instances
without a second roundtrip.

Qdrant REST endpoints used:
  PUT  /collections/{name}                       create
  PUT  /collections/{name}/points?wait=true      upsert
  POST /collections/{name}/points/search         vector search
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .researcher import CorpusRecord

logger = logging.getLogger("oubliette_warden.qdrant")

QDRANT_DEFAULT_URL = "http://127.0.0.1:6333"
DEFAULT_COLLECTION = "nvd_corpus"


@dataclass
class QdrantError(RuntimeError):
    detail: str
    status_code: int | None = None

    def __str__(self) -> str:
        return f"QdrantError: {self.detail}"


class Embedder(Protocol):
    """Minimal contract — anything with ``embed(text) -> list[float]``.

    Implementations may additionally provide ``embed_query`` and
    ``embed_document`` for asymmetric models (nomic-embed-text); the
    retriever and seeder prefer those when present and fall back to
    ``embed`` otherwise.
    """

    def embed(self, text: str) -> list[float]: ...


def _embed_query(embedder: Embedder, text: str) -> list[float]:
    """Use the embedder's query-side method if it has one."""
    fn = getattr(embedder, "embed_query", None)
    return fn(text) if callable(fn) else embedder.embed(text)


def _embed_document(embedder: Embedder, text: str) -> list[float]:
    """Use the embedder's document-side method if it has one."""
    fn = getattr(embedder, "embed_document", None)
    return fn(text) if callable(fn) else embedder.embed(text)


class QdrantTransport:
    """HTTP wrapper. Injectable for unit tests."""

    def __init__(
        self,
        base_url: str = QDRANT_DEFAULT_URL,
        api_key: str | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["api-key"] = self._api_key
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self._base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 — controlled base_url
                text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise QdrantError(
                detail=f"HTTP {exc.code} {exc.reason}: {err_body[:200]}",
                status_code=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise QdrantError(detail=f"network error: {exc}") from exc
        if not text.strip():
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise QdrantError(
                detail=f"non-JSON response: {text[:200]!r}"
            ) from exc

    def put(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("PUT", path, body)

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, body)

    def get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path)


class QdrantRetriever:
    """``Retriever`` Protocol implementation backed by Qdrant + an embedder."""

    def __init__(
        self,
        *,
        embedder: Embedder,
        collection: str = DEFAULT_COLLECTION,
        transport: QdrantTransport | None = None,
    ) -> None:
        self._embedder = embedder
        self._collection = collection
        self._transport = transport or QdrantTransport()

    def retrieve(self, query: str, k: int = 5) -> Sequence[CorpusRecord]:
        vector = _embed_query(self._embedder, query)
        body = {
            "vector": vector,
            "limit": k,
            "with_payload": True,
            "with_vector": False,
        }
        result = self._transport.post(
            f"/collections/{self._collection}/points/search", body
        )
        hits = result.get("result", []) or []
        out: list[CorpusRecord] = []
        for hit in hits:
            payload = hit.get("payload") or {}
            cve_id = payload.get("cve_id")
            if not cve_id:
                continue
            out.append(
                CorpusRecord(
                    cve_id=str(cve_id),
                    description=str(payload.get("description", "")),
                    cvss_severity=payload.get("cvss_severity"),
                    references=list(payload.get("references", []) or []),
                )
            )
        return out


# ----- seeding helper (used by scripts/seed_qdrant.py) ----------------------


def ensure_collection(
    transport: QdrantTransport,
    *,
    collection: str,
    vector_size: int,
    distance: str = "Cosine",
    recreate: bool = False,
) -> None:
    """Create the collection if it doesn't already exist.

    Idempotent: if the collection is present with a matching vector size
    this is a no-op. If it's present with a *different* vector size, we
    raise -- the caller must rerun with ``recreate=True`` to wipe it.
    """
    path = f"/collections/{collection}"

    if recreate:
        # Delete is a no-op if absent; tolerate not-found.
        try:
            transport._request("DELETE", path)  # noqa: SLF001
        except QdrantError as e:
            if e.status_code != 404:
                raise
    else:
        # Probe first so we don't trip Qdrant's 409 "already exists".
        try:
            existing = transport.get(path)
        except QdrantError as e:
            if e.status_code != 404:
                raise
            existing = None
        if existing is not None:
            cfg = (
                existing.get("result", {})
                .get("config", {})
                .get("params", {})
                .get("vectors", {})
            )
            existing_size = cfg.get("size") if isinstance(cfg, dict) else None
            if existing_size and existing_size != vector_size:
                raise QdrantError(
                    detail=(
                        f"collection {collection!r} exists with vector size "
                        f"{existing_size}, but seeder needs {vector_size}. "
                        f"Re-run with --recreate to wipe it."
                    )
                )
            return  # exists, compatible — nothing to do

    body = {
        "vectors": {"size": vector_size, "distance": distance},
    }
    transport.put(path, body)


def upsert_records(
    transport: QdrantTransport,
    embedder: Embedder,
    records: Iterable[CorpusRecord],
    *,
    collection: str = DEFAULT_COLLECTION,
    batch_size: int = 64,
    start_index: int = 0,
    skip_embed_errors: bool = True,
) -> int:
    """Embed and upsert records. Returns the number of points written.

    ``start_index`` offsets the point IDs so a resumed run (after a crash)
    continues numbering where it left off rather than clobbering 1..N.
    Point ID = ``start_index + position`` (1-based position in ``records``),
    which equals the record's line number in the corpus when the caller
    skips the first ``start_index`` lines.

    ``skip_embed_errors`` (default True): if an individual embedding raises
    after the transport's own retries are exhausted, log and skip that one
    record rather than aborting the whole seed.
    """
    written = 0
    skipped = 0
    batch: list[dict[str, Any]] = []

    def _flush() -> None:
        nonlocal written
        if not batch:
            return
        # Pass a copy: we clear() ``batch`` right after, and a transport
        # that retains the reference (or retries) must not see an emptied
        # list.
        transport.put(
            f"/collections/{collection}/points?wait=true",
            {"points": list(batch)},
        )
        written += len(batch)
        batch.clear()

    for offset, rec in enumerate(records):
        point_id = start_index + offset + 1
        text_for_embedding = f"{rec.cve_id}: {rec.description}"
        try:
            vector = _embed_document(embedder, text_for_embedding)
        except Exception as exc:  # noqa: BLE001 — embed backends raise varied types
            if not skip_embed_errors:
                raise
            skipped += 1
            logger.warning(
                "skipping %s (point %d) after embed failure: %s",
                rec.cve_id,
                point_id,
                exc,
            )
            continue
        batch.append(
            {
                "id": point_id,
                "vector": vector,
                "payload": {
                    "cve_id": rec.cve_id,
                    "description": rec.description,
                    "cvss_severity": rec.cvss_severity,
                    "references": list(rec.references),
                },
            }
        )
        if len(batch) >= batch_size:
            _flush()
    _flush()
    if skipped:
        logger.warning("upsert complete: %d written, %d skipped", written, skipped)
    return written
