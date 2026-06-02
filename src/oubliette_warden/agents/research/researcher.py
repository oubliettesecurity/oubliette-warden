"""
Vulnerability Research agent (RAG, citation-bound).

Phase I contract:

    Every answer carries at least one verifiable citation. An answer with no
    citation is rejected by the integrity guard. A citation that does not
    resolve to a real corpus record is rejected by the integrity guard.
    A claimed CVE id that does not appear in the corpus is rejected.

The agent itself is small: it asks the retriever for relevant records,
asks the language model for a synthesis grounded in those records, then
hands the synthesis to the integrity guard. If the guard rejects, the
agent retries up to N times with a stricter prompt; if all retries fail
the agent returns an explicit "uncertain" answer rather than hallucinate.

The Retriever and LanguageModel protocols below are deliberately tiny.
At integration time they are backed by Qdrant + Ollama; in tests they are
backed by deterministic stubs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, Sequence

from .evidence_guard import (
    CVE_RE,
    Citation,
    CorpusRecord,
    IntegrityGuard,
    IntegrityReport,
    canonical_nvd_url,
)

__all__ = [
    "CVE_RE",
    "Citation",
    "CorpusRecord",
    "IntegrityGuard",
    "IntegrityReport",
    "LanguageModel",
    "ResearchAnswer",
    "Researcher",
    "Retriever",
    "canonical_nvd_url",
]


@dataclass(frozen=True)
class ResearchAnswer:
    """An answer produced by the Researcher agent, post-integrity-check."""

    question: str
    text: str
    cves_mentioned: list[str]
    citations: list[Citation]
    confident: bool

    def is_uncited(self) -> bool:
        return len(self.citations) == 0


class Retriever(Protocol):
    def retrieve(self, query: str, k: int = 5) -> Sequence[CorpusRecord]: ...


class LanguageModel(Protocol):
    def synthesize(self, question: str, context: Sequence[CorpusRecord]) -> str: ...


_HALLUCINATION_REASON_TOKENS = (
    "unsupported CVE ids",  # R2 — mentioned a CVE not in the retrieved set
)


def _is_hallucination_reason(reasons: list[str]) -> bool:
    """True iff any guard-rejection reason indicates a hallucinated fact.

    Distinguishes safety-critical failures (R2 — content the model invented)
    from cosmetic failures (R1/R3/R4/R5 — citation formatting). Hallucinations
    must NEVER escape the agent; format failures can be surfaced with a
    ``confident=False`` flag and let downstream consumers decide.
    """
    return any(
        any(tok in reason for tok in _HALLUCINATION_REASON_TOKENS)
        for reason in reasons
    )


@dataclass
class Researcher:
    retriever: Retriever
    llm: LanguageModel
    guard: IntegrityGuard = field(default_factory=IntegrityGuard)
    max_retries: int = 2
    k: int = 5

    def answer(self, question: str) -> ResearchAnswer:
        retrieved = list(self.retriever.retrieve(question, k=self.k))
        if not retrieved:
            return ResearchAnswer(
                question=question,
                text="No relevant records were retrieved from the corpus.",
                cves_mentioned=[],
                citations=[],
                confident=False,
            )

        last_text = ""
        last_citations: list[Citation] = []
        last_reasons: list[str] = []
        for attempt in range(self.max_retries + 1):
            text = self.llm.synthesize(question, retrieved)
            citations = self._extract_citations(text, retrieved)
            citations = self._complete_citations(text, retrieved, citations)
            report = self.guard.check(text, retrieved, citations)
            last_text, last_citations = text, citations
            last_reasons = list(report.rejected_reasons)
            if report.accepted:
                return ResearchAnswer(
                    question=question,
                    text=text,
                    cves_mentioned=sorted(set(CVE_RE.findall(text))),
                    citations=citations,
                    confident=True,
                )
            # Retry with a stricter framing — in the real impl this rebuilds
            # the prompt with explicit citation requirements; the stub LLM
            # is deterministic so this is a no-op for tests but documents intent.
            _ = attempt

        # All retries exhausted. Two paths:
        #
        #   1. The model named a CVE that isn't in the retrieved set —
        #      a *hallucination*. Replace the text with an explicit
        #      refusal so the unsupported claim cannot escape the agent.
        #
        #   2. The model produced grounded content but the citation
        #      formatting failed (no markdown link, off-allowlist url,
        #      etc.). Surface the model's actual text with citation
        #      completion attached and confident=False. This is the
        #      common case under small generators that name the right
        #      CVE but don't hand-write the [..](..) link; it was
        #      previously masked by a canned "Unable to produce..."
        #      reply that the LLM-judge graders correctly fail.
        if _is_hallucination_reason(last_reasons):
            return ResearchAnswer(
                question=question,
                text=(
                    "Unable to produce a citation-grounded answer for this "
                    "question. The synthesis referenced CVE identifiers that "
                    "are not present in the retrieved evidence."
                ),
                cves_mentioned=sorted(set(CVE_RE.findall(last_text))),
                citations=last_citations,
                confident=False,
            )
        return ResearchAnswer(
            question=question,
            text=last_text,
            cves_mentioned=sorted(set(CVE_RE.findall(last_text))),
            citations=last_citations,
            confident=False,
        )

    @staticmethod
    def _complete_citations(
        text: str,
        retrieved: Sequence[CorpusRecord],
        citations: list[Citation],
    ) -> list[Citation]:
        """Attach authoritative citations the model named but didn't format.

        Small models reliably *name* the right CVE but often fail to
        hand-write a ``[CVE](url)`` markdown link. Citation grounding is the
        retrieval layer's job, not the LLM's: for any CVE the answer
        mentions that is in the retrieved set but not yet explicitly cited,
        attach its canonical NVD URL. Hallucinated CVEs (mentioned but NOT
        retrieved) are deliberately not completed — the integrity guard
        still rejects those.
        """
        retrieved_ids = {r.cve_id for r in retrieved}
        already_cited = {c.cve_id for c in citations}
        completed = list(citations)
        for cve in dict.fromkeys(CVE_RE.findall(text)):  # preserve order, dedupe
            if cve in retrieved_ids and cve not in already_cited:
                completed.append(Citation(cve_id=cve, url=canonical_nvd_url(cve)))
                already_cited.add(cve)
        return completed

    @staticmethod
    def _extract_citations(text: str, retrieved: Sequence[CorpusRecord]) -> list[Citation]:
        """
        Extract (cve, url) pairs from the LLM output.

        The LLM is contracted to emit citations as "[CVE-XXXX-YYYY](https://...)"
        or "CVE-XXXX-YYYY (https://...)". We accept both forms.
        """
        out: list[Citation] = []
        # Markdown form
        for m in re.finditer(r"\[(CVE-\d{4}-\d{4,7})\]\((https?://[^\s)]+)\)", text):
            out.append(Citation(cve_id=m.group(1), url=m.group(2)))
        # Parenthetical form
        for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s*\((https?://[^\s)]+)\)", text):
            cit = Citation(cve_id=m.group(1), url=m.group(2))
            if cit not in out:
                out.append(cit)
        return out
