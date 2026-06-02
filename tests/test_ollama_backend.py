"""Tests for the Ollama-backed LanguageModel + Embedder.

Uses an in-memory fake transport so no real Ollama daemon is required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.ollama_backend import (  # noqa: E402
    MAX_EMBED_CHARS,
    OllamaEmbedder,
    OllamaError,
    OllamaLanguageModel,
    OllamaTransport,
)
from oubliette_warden.agents.research.researcher import CorpusRecord  # noqa: E402


class FakeTransport:
    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.posts.append((path, body))
        return self._response


# ----- OllamaLanguageModel -----


def _records() -> list[CorpusRecord]:
    return [
        CorpusRecord(
            cve_id="CVE-2021-44228",
            description="Apache Log4j2 JNDI features used in configuration enable RCE.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
    ]


def test_synthesize_posts_to_generate_endpoint():
    t = FakeTransport({"response": "Log4Shell describes [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)."})
    llm = OllamaLanguageModel(transport=t, model="llama3.1:8b")
    answer = llm.synthesize("What is Log4Shell?", _records())
    assert "[CVE-2021-44228]" in answer
    assert len(t.posts) == 1
    path, body = t.posts[0]
    assert path == "/api/generate"
    assert body["model"] == "llama3.1:8b"
    assert body["stream"] is False
    assert "Log4Shell" in body["prompt"]
    assert "CVE-2021-44228" in body["prompt"]


def test_synthesize_includes_citation_rules_in_prompt():
    t = FakeTransport({"response": "ok"})
    llm = OllamaLanguageModel(transport=t)
    llm.synthesize("Tell me about Log4Shell.", _records())
    _, body = t.posts[0]
    prompt = body["prompt"]
    # Rules R1-R5 must all be present in the system prompt.
    for rule in ("R1.", "R2.", "R3.", "R4.", "R5."):
        assert rule in prompt, f"missing rule {rule} in prompt"


def test_synthesize_lists_record_references_in_prompt():
    t = FakeTransport({"response": "ok"})
    llm = OllamaLanguageModel(transport=t)
    llm.synthesize("Tell me about Log4Shell.", _records())
    _, body = t.posts[0]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in body["prompt"]


def test_synthesize_rejects_non_string_response():
    t = FakeTransport({"response": 42})
    llm = OllamaLanguageModel(transport=t)
    with pytest.raises(OllamaError):
        llm.synthesize("q", _records())


def test_synthesize_empty_response_returns_empty_string():
    t = FakeTransport({"response": ""})
    llm = OllamaLanguageModel(transport=t)
    assert llm.synthesize("q", _records()) == ""


def test_temperature_and_max_tokens_flow_to_options():
    t = FakeTransport({"response": "ok"})
    llm = OllamaLanguageModel(transport=t, temperature=0.4, max_tokens=999)
    llm.synthesize("q", _records())
    _, body = t.posts[0]
    assert body["options"]["temperature"] == 0.4
    assert body["options"]["num_predict"] == 999


# ----- OllamaEmbedder -----


def test_embed_posts_to_embeddings_endpoint():
    t = FakeTransport({"embedding": [0.1, 0.2, 0.3]})
    emb = OllamaEmbedder(transport=t, model="nomic-embed-text")
    vec = emb.embed("hello")
    assert vec == [0.1, 0.2, 0.3]
    path, body = t.posts[0]
    assert path == "/api/embeddings"
    assert body["model"] == "nomic-embed-text"
    assert body["prompt"] == "hello"


def test_embed_rejects_missing_embedding_key():
    t = FakeTransport({"oops": "no embedding here"})
    emb = OllamaEmbedder(transport=t)
    with pytest.raises(OllamaError):
        emb.embed("hello")


def test_embed_rejects_non_numeric_vector():
    t = FakeTransport({"embedding": [0.1, "nope", 0.3]})
    emb = OllamaEmbedder(transport=t)
    with pytest.raises(OllamaError):
        emb.embed("hello")


def test_embed_coerces_ints_to_floats():
    t = FakeTransport({"embedding": [1, 2, 3]})
    emb = OllamaEmbedder(transport=t)
    vec = emb.embed("hello")
    assert vec == [1.0, 2.0, 3.0]
    assert all(isinstance(x, float) for x in vec)


def test_embed_truncates_over_long_input():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t)
    long_text = "x" * (MAX_EMBED_CHARS + 5000)
    emb.embed(long_text)
    _, body = t.posts[0]
    assert len(body["prompt"]) == MAX_EMBED_CHARS


def test_embed_does_not_truncate_short_input():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t)
    emb.embed("short")
    _, body = t.posts[0]
    assert body["prompt"] == "short"


# ----- nomic task prefixes -----


def test_nomic_embedder_applies_document_prefix():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t, model="nomic-embed-text")
    emb.embed_document("CVE-2021-44228: Log4j RCE")
    _, body = t.posts[0]
    assert body["prompt"] == "search_document: CVE-2021-44228: Log4j RCE"


def test_nomic_embedder_applies_query_prefix():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t, model="nomic-embed-text")
    emb.embed_query("Java logging JNDI RCE")
    _, body = t.posts[0]
    assert body["prompt"] == "search_query: Java logging JNDI RCE"


def test_raw_embed_has_no_prefix():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t, model="nomic-embed-text")
    emb.embed("probe")
    _, body = t.posts[0]
    assert body["prompt"] == "probe"


def test_unknown_model_gets_no_prefix_by_default():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t, model="all-minilm")
    emb.embed_document("doc")
    emb.embed_query("q")
    assert t.posts[0][1]["prompt"] == "doc"
    assert t.posts[1][1]["prompt"] == "q"


def test_mxbai_model_uses_represent_query_prefix_and_no_doc_prefix():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(transport=t, model="mxbai-embed-large")
    emb.embed_query("Java logging JNDI RCE")
    emb.embed_document("CVE-2021-44228: Log4j RCE")
    assert t.posts[0][1]["prompt"] == (
        "Represent this sentence for searching relevant passages: "
        "Java logging JNDI RCE"
    )
    # mxbai documents get NO prefix.
    assert t.posts[1][1]["prompt"] == "CVE-2021-44228: Log4j RCE"


def test_prefixes_are_overridable():
    t = FakeTransport({"embedding": [0.1]})
    emb = OllamaEmbedder(
        transport=t,
        model="nomic-embed-text",
        query_prefix="Q: ",
        document_prefix="D: ",
    )
    emb.embed_query("x")
    emb.embed_document("y")
    assert t.posts[0][1]["prompt"] == "Q: x"
    assert t.posts[1][1]["prompt"] == "D: y"


# ----- OllamaTransport retry behavior -----


class FlakyTransportProbe:
    """A urllib stand-in: raises HTTPError N times, then returns a body."""

    def __init__(self, fail_times: int, code: int = 500) -> None:
        self.fail_times = fail_times
        self.code = code
        self.attempts = 0


def _patch_urlopen(monkeypatch, *, fail_times: int, code: int, payload: dict):
    import urllib.request

    state = {"attempts": 0}

    class _Resp:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        state["attempts"] += 1
        if state["attempts"] <= fail_times:
            raise urllib.error.HTTPError(
                req.full_url, code, f"err{code}", hdrs=None, fp=None
            )
        return _Resp(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return state


def test_transport_retries_5xx_then_succeeds(monkeypatch):
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda s: None)  # no real backoff wait
    state = _patch_urlopen(
        monkeypatch, fail_times=2, code=500, payload={"embedding": [0.5]}
    )
    t = OllamaTransport(max_retries=4, backoff_base=1.0)
    result = t.post("/api/embeddings", {"model": "m", "prompt": "p"})
    assert result == {"embedding": [0.5]}
    assert state["attempts"] == 3  # 2 failures + 1 success


def test_transport_gives_up_after_max_retries(monkeypatch):
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda s: None)
    _patch_urlopen(monkeypatch, fail_times=99, code=500, payload={})
    t = OllamaTransport(max_retries=2, backoff_base=1.0)
    with pytest.raises(OllamaError) as ei:
        t.post("/api/embeddings", {"model": "m", "prompt": "p"})
    assert ei.value.status_code == 500
    assert ei.value.retryable is True


def test_transport_does_not_retry_4xx(monkeypatch):
    import time as _time

    sleeps = []
    monkeypatch.setattr(_time, "sleep", lambda s: sleeps.append(s))
    state = _patch_urlopen(monkeypatch, fail_times=99, code=400, payload={})
    t = OllamaTransport(max_retries=4)
    with pytest.raises(OllamaError) as ei:
        t.post("/api/generate", {"model": "m", "prompt": "p"})
    assert ei.value.status_code == 400
    assert ei.value.retryable is False
    assert state["attempts"] == 1  # no retries on a client error
    assert sleeps == []
