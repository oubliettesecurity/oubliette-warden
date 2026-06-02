"""Tests for the Qdrant-backed Retriever + seeding helpers.

In-memory fake transport. No real Qdrant container required.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.qdrant_backend import (  # noqa: E402
    QdrantError,
    QdrantRetriever,
    ensure_collection,
    upsert_records,
)
from oubliette_warden.agents.research.researcher import CorpusRecord  # noqa: E402


class FakeQdrantTransport:
    def __init__(
        self,
        *,
        search_result: dict[str, Any] | None = None,
        get_result: dict[str, Any] | None = None,
        get_status: int | None = None,
    ) -> None:
        """If ``get_status`` is set, GET raises QdrantError with that code.
        Otherwise GET returns ``get_result`` (default empty dict).
        """
        self._search_result = search_result or {"result": []}
        self._get_result = get_result
        self._get_status = get_status
        self.calls: list[tuple[str, str, dict | None]] = []

    def _request(self, method: str, path: str, body=None):
        self.calls.append((method, path, body))
        return {}

    def put(self, path: str, body=None):
        self.calls.append(("PUT", path, body))
        return {}

    def post(self, path: str, body):
        self.calls.append(("POST", path, body))
        if path.endswith("/points/search"):
            return self._search_result
        return {}

    def get(self, path: str):
        self.calls.append(("GET", path, None))
        if self._get_status is not None:
            raise QdrantError(
                detail=f"HTTP {self._get_status} not found",
                status_code=self._get_status,
            )
        return self._get_result or {}


class FakeEmbedder:
    def __init__(self, vector: list[float] | None = None) -> None:
        self._vector = vector or [0.1, 0.2, 0.3]
        self.calls: list[str] = []

    def embed(self, text: str) -> list[float]:
        self.calls.append(text)
        return list(self._vector)


class FlakyEmbedder:
    """Raises on records whose cve_id is in ``fail_on``; embeds otherwise."""

    def __init__(self, fail_on: set[str]) -> None:
        self._fail_on = fail_on
        self.calls: list[str] = []

    def embed(self, text: str) -> list[float]:
        self.calls.append(text)
        cve = text.split(":", 1)[0]
        if cve in self._fail_on:
            raise RuntimeError(f"simulated embed failure for {cve}")
        return [0.1, 0.2, 0.3]


# ----- ensure_collection -----


def test_ensure_collection_creates_when_absent():
    # GET returns 404 -> we PUT to create.
    t = FakeQdrantTransport(get_status=404)
    ensure_collection(t, collection="x", vector_size=768)
    methods = [c[0] for c in t.calls]
    assert methods == ["GET", "PUT"]
    last_put = [c for c in t.calls if c[0] == "PUT"][0]
    assert last_put[2] == {"vectors": {"size": 768, "distance": "Cosine"}}


def test_ensure_collection_is_noop_when_present_with_matching_size():
    # GET succeeds with a matching vector size -> no PUT.
    t = FakeQdrantTransport(
        get_result={
            "result": {
                "config": {"params": {"vectors": {"size": 768, "distance": "Cosine"}}}
            }
        }
    )
    ensure_collection(t, collection="x", vector_size=768)
    methods = [c[0] for c in t.calls]
    assert methods == ["GET"], f"expected only GET, got {methods}"


def test_ensure_collection_raises_when_present_with_mismatched_size():
    t = FakeQdrantTransport(
        get_result={
            "result": {"config": {"params": {"vectors": {"size": 384}}}}
        }
    )
    with pytest.raises(QdrantError, match="vector size 384"):
        ensure_collection(t, collection="x", vector_size=768)


def test_ensure_collection_recreate_deletes_first():
    t = FakeQdrantTransport()
    ensure_collection(t, collection="x", vector_size=768, recreate=True)
    methods = [c[0] for c in t.calls]
    assert methods == ["DELETE", "PUT"]


def test_ensure_collection_recreate_tolerates_404_on_delete():
    # When the collection doesn't exist, DELETE returns 404; ensure_collection
    # should swallow it and proceed to PUT.
    t = FakeQdrantTransport()

    # Override _request to raise 404 on DELETE.
    orig_request = t._request

    def patched(method: str, path: str, body=None):
        if method == "DELETE":
            raise QdrantError(detail="HTTP 404 not found", status_code=404)
        return orig_request(method, path, body)

    t._request = patched  # type: ignore[method-assign]
    ensure_collection(t, collection="x", vector_size=768, recreate=True)
    # PUT must still happen even after the DELETE 404.
    assert any(c[0] == "PUT" for c in t.calls)


def test_ensure_collection_recreate_reraises_non_404_delete_errors():
    t = FakeQdrantTransport()

    def patched(method: str, path: str, body=None):
        if method == "DELETE":
            raise QdrantError(detail="HTTP 500 server error", status_code=500)
        return {}

    t._request = patched  # type: ignore[method-assign]
    with pytest.raises(QdrantError, match="500"):
        ensure_collection(t, collection="x", vector_size=768, recreate=True)


# ----- upsert_records -----


def test_upsert_records_embeds_and_uploads():
    t = FakeQdrantTransport()
    emb = FakeEmbedder()
    records = [
        CorpusRecord(
            cve_id="CVE-2017-0144",
            description="EternalBlue SMBv1 RCE",
            cvss_severity="HIGH",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        ),
    ]
    written = upsert_records(t, emb, records, collection="x", batch_size=10)
    assert written == 1
    # Embedder was called once with the joined cve_id + description.
    assert emb.calls == ["CVE-2017-0144: EternalBlue SMBv1 RCE"]
    # Last PUT is to /collections/x/points?wait=true.
    last_put = [c for c in t.calls if c[1].startswith("/collections/x/points")][-1]
    method, path, body = last_put
    assert method == "PUT"
    assert "wait=true" in path
    point = body["points"][0]
    assert point["payload"]["cve_id"] == "CVE-2017-0144"
    assert point["payload"]["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
    ]


def test_upsert_records_batches():
    t = FakeQdrantTransport()
    emb = FakeEmbedder()
    records = [
        CorpusRecord(cve_id=f"CVE-2020-{i:04d}", description="x", cvss_severity=None)
        for i in range(5)
    ]
    written = upsert_records(t, emb, records, collection="x", batch_size=2)
    assert written == 5
    # 3 PUT batches of points: 2 + 2 + 1.
    point_puts = [c for c in t.calls if c[1].startswith("/collections/x/points")]
    assert len(point_puts) == 3
    assert len(point_puts[0][2]["points"]) == 2
    assert len(point_puts[1][2]["points"]) == 2
    assert len(point_puts[2][2]["points"]) == 1


def test_upsert_skips_records_with_embed_errors():
    t = FakeQdrantTransport()
    emb = FlakyEmbedder(fail_on={"CVE-2020-0002"})
    records = [
        CorpusRecord(cve_id=f"CVE-2020-{i:04d}", description="x", cvss_severity=None)
        for i in range(4)
    ]
    written = upsert_records(t, emb, records, collection="x", batch_size=10)
    # 4 records, 1 fails -> 3 written.
    assert written == 3
    point_ids = [
        p["id"] for c in t.calls if c[1].startswith("/collections/x/points")
        for p in c[2]["points"]
    ]
    # The failing record (position 3, point_id 3) is absent; others present.
    assert 3 not in point_ids
    assert {1, 2, 4} == set(point_ids)


def test_upsert_reraises_embed_error_when_skip_disabled():
    t = FakeQdrantTransport()
    emb = FlakyEmbedder(fail_on={"CVE-2020-0000"})
    records = [CorpusRecord(cve_id="CVE-2020-0000", description="x", cvss_severity=None)]
    with pytest.raises(RuntimeError, match="simulated embed failure"):
        upsert_records(t, emb, records, collection="x", skip_embed_errors=False)


def test_upsert_start_index_offsets_point_ids():
    t = FakeQdrantTransport()
    emb = FakeEmbedder()
    records = [
        CorpusRecord(cve_id=f"CVE-2020-{i:04d}", description="x", cvss_severity=None)
        for i in range(3)
    ]
    written = upsert_records(t, emb, records, collection="x", start_index=16500)
    assert written == 3
    point_ids = [
        p["id"] for c in t.calls if c[1].startswith("/collections/x/points")
        for p in c[2]["points"]
    ]
    # Resume offset: ids continue from 16501.
    assert point_ids == [16501, 16502, 16503]


# ----- QdrantRetriever -----


def test_retriever_returns_corpus_records_from_hits():
    t = FakeQdrantTransport(
        search_result={
            "result": [
                {
                    "id": 1,
                    "score": 0.97,
                    "payload": {
                        "cve_id": "CVE-2021-44228",
                        "description": "Log4j JNDI RCE",
                        "cvss_severity": "CRITICAL",
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        ],
                    },
                },
            ],
        }
    )
    emb = FakeEmbedder()
    r = QdrantRetriever(embedder=emb, transport=t, collection="x")
    out = r.retrieve("Log4Shell", k=5)
    assert len(out) == 1
    assert out[0].cve_id == "CVE-2021-44228"
    assert out[0].cvss_severity == "CRITICAL"
    # Search POST was made with the embedded vector and limit=k.
    search_call = [c for c in t.calls if c[1].endswith("/points/search")][0]
    method, path, body = search_call
    assert method == "POST"
    assert body["vector"] == [0.1, 0.2, 0.3]
    assert body["limit"] == 5
    assert body["with_payload"] is True


def test_retriever_skips_hits_without_cve_id():
    t = FakeQdrantTransport(
        search_result={
            "result": [
                {"id": 1, "payload": {"description": "no cve_id"}},
                {"id": 2, "payload": {"cve_id": "CVE-2020-0001", "description": "ok"}},
            ]
        }
    )
    emb = FakeEmbedder()
    r = QdrantRetriever(embedder=emb, transport=t)
    out = r.retrieve("q")
    assert len(out) == 1
    assert out[0].cve_id == "CVE-2020-0001"


def test_retriever_handles_empty_search_result():
    t = FakeQdrantTransport(search_result={"result": []})
    emb = FakeEmbedder()
    r = QdrantRetriever(embedder=emb, transport=t)
    assert list(r.retrieve("q")) == []


class PrefixAwareEmbedder:
    """Embedder exposing embed_query/embed_document — records which was used."""

    def __init__(self) -> None:
        self.used: list[str] = []

    def embed(self, text: str) -> list[float]:
        self.used.append(f"embed:{text}")
        return [0.0]

    def embed_query(self, text: str) -> list[float]:
        self.used.append(f"query:{text}")
        return [0.1, 0.2, 0.3]

    def embed_document(self, text: str) -> list[float]:
        self.used.append(f"doc:{text}")
        return [0.1, 0.2, 0.3]


def test_retriever_prefers_embed_query_when_available():
    t = FakeQdrantTransport(search_result={"result": []})
    emb = PrefixAwareEmbedder()
    r = QdrantRetriever(embedder=emb, transport=t)
    r.retrieve("Log4Shell")
    assert emb.used == ["query:Log4Shell"]


def test_upsert_prefers_embed_document_when_available():
    t = FakeQdrantTransport()
    emb = PrefixAwareEmbedder()
    records = [CorpusRecord(cve_id="CVE-2021-44228", description="Log4j", cvss_severity=None)]
    upsert_records(t, emb, records, collection="x")
    assert emb.used == ["doc:CVE-2021-44228: Log4j"]


def test_upsert_falls_back_to_embed_without_prefix_methods():
    # FakeEmbedder has only embed(); upsert must still work.
    t = FakeQdrantTransport()
    emb = FakeEmbedder()
    records = [CorpusRecord(cve_id="CVE-2020-0001", description="x", cvss_severity=None)]
    written = upsert_records(t, emb, records, collection="x")
    assert written == 1
    assert emb.calls == ["CVE-2020-0001: x"]
