"""Ollama-backed implementations of the Researcher's Protocols.

Two adapters:

  - ``OllamaLanguageModel`` — generation; implements ``LanguageModel``
  - ``OllamaEmbedder`` — embeddings; used by ``QdrantRetriever``

Both speak HTTP to a local Ollama daemon (default ``http://127.0.0.1:11434``)
via ``urllib`` so we don't add a runtime dependency. The CLIENT objects can
be injected for unit tests.

Ollama API reference:
  - POST /api/generate         -> single-shot completion
  - POST /api/embeddings       -> single-vector embedding

Phase I default models:
  - generation: ``llama3.1:8b`` (good reasoning, runs on a laptop)
  - embedding:  ``nomic-embed-text`` (768-dim, fast, defaults to CPU OK)

The ``synthesize`` prompt builds a strict citation-emission instruction so
the integrity guard in ``evidence_guard.py`` will accept the output. If
the model returns non-cited text, the guard rejects it and the Researcher
agent retries with stricter framing — that retry loop lives in
``researcher.Researcher.answer``, not here.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .researcher import CorpusRecord

logger = logging.getLogger("oubliette_warden.ollama")

OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"
OLLAMA_DEFAULT_GEN_MODEL = "llama3.1:8b"
OLLAMA_DEFAULT_EMBED_MODEL = "nomic-embed-text"

# nomic-embed-text accepts ~8192 tokens (~32K chars worst case, but Ollama
# can 500 well before that on some builds). Cap the embedding input
# conservatively so a single over-long CVE description can't abort a seed.
MAX_EMBED_CHARS = 6000

# Several embedding models are *asymmetric*: they were trained with
# task-instruction prefixes and retrieval quality collapses without them.
# The prefixes differ per model family, so map (query_prefix,
# document_prefix) by a model-name substring. Models not in the table get
# empty prefixes. All values are overridable via the OllamaEmbedder ctor.
NOMIC_QUERY_PREFIX = "search_query: "
NOMIC_DOCUMENT_PREFIX = "search_document: "
# mxbai-embed-large / bge: query gets the "represent this sentence" prompt,
# documents get no prefix.
MXBAI_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

_EMBED_PREFIXES: dict[str, tuple[str, str]] = {
    "nomic": (NOMIC_QUERY_PREFIX, NOMIC_DOCUMENT_PREFIX),
    "mxbai": (MXBAI_QUERY_PREFIX, ""),
    "bge": (MXBAI_QUERY_PREFIX, ""),
}


def _default_prefixes(model: str) -> tuple[str, str]:
    """Return (query_prefix, document_prefix) for a model name."""
    lo = model.lower()
    for key, prefixes in _EMBED_PREFIXES.items():
        if key in lo:
            return prefixes
    return ("", "")


SYNTHESIS_SYSTEM_PROMPT = """You are a citation-bound vulnerability research assistant.

You MUST follow these rules. Violations cause your answer to be rejected.

R1. Use ONLY information from the retrieved corpus records I provide below.
    Do not invent CVE identifiers or facts that are not in the records.
R2. Every CVE id you mention must come from the retrieved records.
R3. When you cite, format the citation as [CVE-XXXX-YYYY](URL) using a URL
    from that CVE's "references" list. Do not invent URLs. If you cannot
    construct a markdown link, naming the CVE plainly is also acceptable
    -- the integrity layer will attach the canonical NVD URL for you.
R4. ANSWER whenever any retrieved record matches the question. Decline only
    when NO retrieved record is relevant to the question -- not merely
    because details are sparse. A correct CVE identification with a
    one-sentence summary is a complete answer.
R5. Plain text answer in 1-3 sentences. No JSON. No code blocks.
"""


@dataclass
class OllamaError(RuntimeError):
    """Wraps any HTTP or JSON error from the Ollama daemon."""

    detail: str
    status_code: int | None = None
    retryable: bool = False

    def __str__(self) -> str:
        return f"OllamaError: {self.detail}"


class OllamaTransport:
    """Tiny urllib-based POST wrapper with retry-on-transient-error.

    Ollama returns HTTP 500 on a variety of transient conditions (model
    briefly OOM, GPU contention, a single bad input). During a long
    embedding seed those 500s are common and should not abort the run.
    5xx and network/timeout errors are retried with exponential backoff;
    4xx (client errors) are surfaced immediately.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_DEFAULT_URL,
        timeout_seconds: int = 120,
        max_retries: int = 4,
        backoff_base: float = 1.5,
        backoff_cap_seconds: float = 15.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap_seconds

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        last_exc: OllamaError | None = None
        for attempt in range(self._max_retries + 1):
            try:
                return self._post_once(path, body)
            except OllamaError as exc:
                last_exc = exc
                if not exc.retryable or attempt == self._max_retries:
                    raise
                delay = min(self._backoff_base**attempt, self._backoff_cap)
                logger.warning(
                    "Ollama %s (attempt %d/%d) — retrying in %.1fs: %s",
                    path,
                    attempt + 1,
                    self._max_retries + 1,
                    delay,
                    exc.detail,
                )
                time.sleep(delay)
        # Unreachable: the loop either returns or raises.
        assert last_exc is not None
        raise last_exc

    def _post_once(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._base + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 — controlled base_url
                text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            # 5xx is transient and retryable; 4xx is a client error.
            raise OllamaError(
                detail=f"HTTP {exc.code} {exc.reason}",
                status_code=exc.code,
                retryable=exc.code >= 500,
            ) from exc
        except urllib.error.URLError as exc:
            raise OllamaError(
                detail=f"network error talking to Ollama: {exc}",
                retryable=True,
            ) from exc
        except TimeoutError as exc:
            raise OllamaError(
                detail="Ollama request timed out", retryable=True
            ) from exc
        if not text.strip():
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise OllamaError(
                detail=f"Ollama returned non-JSON: {text[:200]!r}"
            ) from exc


class OllamaLanguageModel:
    """``LanguageModel`` Protocol implementation backed by Ollama."""

    def __init__(
        self,
        *,
        model: str = OLLAMA_DEFAULT_GEN_MODEL,
        transport: OllamaTransport | None = None,
        temperature: float = 0.1,
        max_tokens: int = 400,
    ) -> None:
        self._model = model
        self._transport = transport or OllamaTransport()
        self._temperature = temperature
        self._max_tokens = max_tokens

    def synthesize(self, question: str, context: Sequence[CorpusRecord]) -> str:
        prompt = self._build_prompt(question, context)
        body = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_predict": self._max_tokens,
            },
        }
        result = self._transport.post("/api/generate", body)
        text = result.get("response", "")
        if not isinstance(text, str):
            raise OllamaError(detail=f"unexpected response shape: {result!r}")
        return text.strip()

    # ----- prompt construction -----

    @staticmethod
    def _build_prompt(question: str, context: Sequence[CorpusRecord]) -> str:
        block_lines = [SYNTHESIS_SYSTEM_PROMPT, "", "Retrieved corpus records:"]
        for r in context:
            refs = "; ".join(r.references) if r.references else "(no references)"
            severity = r.cvss_severity or "unknown"
            block_lines.append(
                f"- {r.cve_id} (CVSS {severity}): {r.description}\n"
                f"  references: {refs}"
            )
        block_lines.append("")
        block_lines.append(f"Question: {question}")
        block_lines.append("Answer:")
        return "\n".join(block_lines)


class OllamaEmbedder:
    """Wrap Ollama's /api/embeddings endpoint into a callable.

    Exposes three methods:
      - ``embed_document(text)`` — index-side, applies the document prefix
      - ``embed_query(text)``    — search-side, applies the query prefix
      - ``embed(text)``          — raw, no prefix (probing / back-compat)

    The asymmetric prefixes are essential for nomic-embed-text; without
    them, query↔document similarity is near-random at corpus scale.
    """

    def __init__(
        self,
        *,
        model: str = OLLAMA_DEFAULT_EMBED_MODEL,
        transport: OllamaTransport | None = None,
        query_prefix: str | None = None,
        document_prefix: str | None = None,
    ) -> None:
        self._model = model
        self._transport = transport or OllamaTransport()
        default_q, default_d = _default_prefixes(model)
        self._query_prefix = query_prefix if query_prefix is not None else default_q
        self._document_prefix = (
            document_prefix if document_prefix is not None else default_d
        )

    def _embed_raw(self, text: str) -> list[float]:
        # Truncate over-long inputs: nomic-embed-text has a context limit
        # and some Ollama builds 500 rather than truncate. The leading
        # prefix + CVE id + description carries the discriminative signal,
        # so a head-truncation preserves retrieval quality.
        if len(text) > MAX_EMBED_CHARS:
            text = text[:MAX_EMBED_CHARS]
        body = {"model": self._model, "prompt": text}
        result = self._transport.post("/api/embeddings", body)
        vec = result.get("embedding")
        if not isinstance(vec, list) or not all(isinstance(x, (int, float)) for x in vec):
            raise OllamaError(detail=f"unexpected embedding response: {result!r}")
        return [float(x) for x in vec]

    def embed(self, text: str) -> list[float]:
        """Raw embedding, no task prefix. Used for dimension probing."""
        return self._embed_raw(text)

    def embed_query(self, text: str) -> list[float]:
        return self._embed_raw(self._query_prefix + text)

    def embed_document(self, text: str) -> list[float]:
        return self._embed_raw(self._document_prefix + text)
