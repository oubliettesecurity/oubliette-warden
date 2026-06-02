"""Unit tests for the Researcher agent + IntegrityGuard."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.researcher import (  # noqa: E402
    Citation,
    CorpusRecord,
    IntegrityGuard,
    Researcher,
)
from oubliette_warden.agents.research.stub_backends import (  # noqa: E402
    CannedLLM,
    CannedRetriever,
    seed_researcher,
)


@pytest.fixture
def corpus_two():
    return [
        CorpusRecord(
            cve_id="CVE-2021-44228",
            description="Log4Shell.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        CorpusRecord(
            cve_id="CVE-2021-26855",
            description="ProxyLogon.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
        ),
    ]


def test_citation_well_formed():
    c = Citation(cve_id="CVE-2021-44228", url="https://x.example/cve")
    assert c.is_well_formed()


def test_citation_rejects_bad_id():
    c = Citation(cve_id="not-a-cve", url="https://x.example")
    assert not c.is_well_formed()


def test_citation_rejects_non_http_url():
    c = Citation(cve_id="CVE-2021-44228", url="ftp://x.example")
    assert not c.is_well_formed()


def test_guard_accepts_well_grounded(corpus_two):
    guard = IntegrityGuard()
    answer = "CVE-2021-44228 is the Log4Shell vulnerability (https://nvd.nist.gov/vuln/detail/CVE-2021-44228)."
    citations = [Citation("CVE-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228")]
    rep = guard.check(answer, corpus_two, citations)
    assert rep.accepted, rep.rejected_reasons


def test_guard_rejects_unsupported_cve(corpus_two):
    guard = IntegrityGuard()
    answer = "CVE-2099-99999 explains the entire universe."
    rep = guard.check(answer, corpus_two, [])
    assert not rep.accepted
    assert any("unsupported" in r for r in rep.rejected_reasons)


def test_guard_rejects_no_citations(corpus_two):
    guard = IntegrityGuard()
    answer = "CVE-2021-44228 is bad."
    rep = guard.check(answer, corpus_two, [])
    assert not rep.accepted
    assert any("no citations" in r for r in rep.rejected_reasons)


def test_guard_rejects_citation_url_not_in_corpus(corpus_two):
    guard = IntegrityGuard()
    answer = "CVE-2021-44228 (https://evil.example/cve)."
    citations = [Citation("CVE-2021-44228", "https://evil.example/cve")]
    rep = guard.check(answer, corpus_two, citations)
    assert not rep.accepted
    assert any("url not in corpus" in r for r in rep.rejected_reasons)


def test_researcher_returns_uncertain_when_corpus_empty():
    r = Researcher(retriever=CannedRetriever(corpus=[]), llm=CannedLLM())
    a = r.answer("What is CVE-2021-44228?")
    assert not a.confident
    assert a.is_uncited()


def test_researcher_extracts_markdown_citations():
    text = "See [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) for details."
    cites = Researcher._extract_citations(text, [])
    assert len(cites) == 1
    assert cites[0].cve_id == "CVE-2021-44228"


def test_researcher_extracts_parenthetical_citations():
    text = "ProxyLogon is CVE-2021-26855 (https://nvd.nist.gov/vuln/detail/CVE-2021-26855)."
    cites = Researcher._extract_citations(text, [])
    assert any(c.cve_id == "CVE-2021-26855" for c in cites)


def test_researcher_end_to_end_against_seed_corpus():
    retriever, llm = seed_researcher()
    r = Researcher(retriever=retriever, llm=llm)
    a = r.answer("Tell me about CVE-2021-44228 Log4Shell.")
    assert a.confident
    assert "CVE-2021-44228" in a.cves_mentioned
    assert any(c.cve_id == "CVE-2021-44228" for c in a.citations)


# ----- citation completion (added for B4: small models name but don't cite) -----


class _AllRetriever:
    """Returns the whole corpus regardless of query (isolates completion logic)."""

    def __init__(self, corpus):
        self._corpus = corpus

    def retrieve(self, query, k=5):
        return list(self._corpus)[:k]


class _NamesButDoesNotCiteLLM:
    """Synthesizes an answer that names the right CVE but emits no markdown link."""

    def synthesize(self, question, context):
        # Names CVE-2021-44228 in prose with NO [..](..) citation.
        return "This is CVE-2021-44228, the Apache Log4j2 JNDI lookup RCE."


def test_completion_attaches_nvd_url_for_named_retrieved_cve(corpus_two):
    from oubliette_warden.agents.research.researcher import canonical_nvd_url

    r = Researcher(
        retriever=_AllRetriever(corpus_two),
        llm=_NamesButDoesNotCiteLLM(),
    )
    ans = r.answer("Which CVE is the Java logging JNDI RCE?")
    assert ans.confident, "completion should let an uncited-but-named answer pass"
    assert "CVE-2021-44228" in ans.cves_mentioned
    urls = {c.url for c in ans.citations}
    assert canonical_nvd_url("CVE-2021-44228") in urls


class _NamesUnretrievedCveLLM:
    """Names a CVE that is NOT in the retrieved set — a hallucination."""

    def synthesize(self, question, context):
        return "This is CVE-2099-0001, a totally invented vulnerability."


def test_completion_does_not_rescue_hallucinated_cve(corpus_two):
    r = Researcher(
        retriever=_AllRetriever(corpus_two),
        llm=_NamesUnretrievedCveLLM(),
    )
    ans = r.answer("Tell me about something")
    # The hallucinated CVE is not retrieved, so completion must NOT cite it,
    # and the guard must reject -> not confident.
    assert not ans.confident


class _PlainTextLLM:
    """Names the right retrieved CVE but emits NOTHING citation-shaped —
    no [..](..) link, no parenthetical URL. Tests the format-failure surface."""

    def synthesize(self, question, context):
        # Names CVE-2021-44228 plainly. No markdown link, no URL anywhere.
        return "The Apache Log4j2 JNDI lookup remote code execution is CVE-2021-44228."


def test_format_failure_surfaces_models_actual_text(corpus_two):
    # With completion attaching the canonical NVD url, this should fully
    # pass. The intent of this test is to lock in the surface-on-fail
    # behavior: even if completion didn't run, the answer must NOT be
    # replaced by the generic "Unable to produce..." refusal -- the
    # judge needs the model's real words to grade against the rubric.
    r = Researcher(
        retriever=_AllRetriever(corpus_two),
        llm=_PlainTextLLM(),
    )
    ans = r.answer("Which CVE is the Java logging JNDI RCE?")
    # The model's words must survive — never the canned "Unable to..." text.
    assert "Unable to produce" not in ans.text
    assert "CVE-2021-44228" in ans.text


class _HallucinatesUnretrievedCveLLM:
    """Mentions a CVE that's not in the retrieved set — a real hallucination."""

    def synthesize(self, question, context):
        return "This sounds like CVE-2099-0001 to me."


def test_hallucination_still_replaced_by_refusal(corpus_two):
    # When the guard rejects because an unsupported CVE was named (R2),
    # the unsafe text must NOT escape -- replace with refusal.
    r = Researcher(
        retriever=_AllRetriever(corpus_two),
        llm=_HallucinatesUnretrievedCveLLM(),
    )
    ans = r.answer("What CVE is this?")
    assert not ans.confident
    assert "CVE-2099-0001" not in ans.text
    assert "not present in the retrieved evidence" in ans.text


def test_hallucination_detector_uses_guard_reasons():
    from oubliette_warden.agents.research.researcher import _is_hallucination_reason

    assert _is_hallucination_reason(
        ["answer mentions unsupported CVE ids: ['CVE-2099-0001']"]
    )
    assert not _is_hallucination_reason(["answer has no citations (R1)"])
    assert not _is_hallucination_reason(
        ["citation url not in accepted source prefixes (R3): https://x"]
    )


def test_guard_accepts_canonical_nvd_url_even_if_not_in_references():
    # Record whose references do NOT include the canonical NVD url.
    rec = CorpusRecord(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        cvss_severity="CRITICAL",
        references=["https://logging.apache.org/log4j/2.x/security.html"],
    )
    from oubliette_warden.agents.research.researcher import canonical_nvd_url

    guard = IntegrityGuard()
    cit = Citation(cve_id="CVE-2021-44228", url=canonical_nvd_url("CVE-2021-44228"))
    report = guard.check("see CVE-2021-44228", [rec], [cit])
    assert report.accepted, report.rejected_reasons
