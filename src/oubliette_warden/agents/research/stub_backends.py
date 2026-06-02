"""
Deterministic Retriever and LanguageModel stubs.

These are used by the eval harness and tests so the Researcher pipeline can be
exercised end-to-end without Qdrant or Ollama. At integration time they are
swapped for real backends; the agent code is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .researcher import CVE_RE, CorpusRecord, LanguageModel, Retriever


@dataclass
class CannedRetriever:
    """Returns a fixed corpus, ranked by CVE-id token overlap with the query."""

    corpus: list[CorpusRecord]

    def retrieve(self, query: str, k: int = 5) -> Sequence[CorpusRecord]:
        q_cves = set(CVE_RE.findall(query))
        q_tokens = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]+", query.lower()))
        scored: list[tuple[int, CorpusRecord]] = []
        for r in self.corpus:
            score = 0
            if r.cve_id in q_cves:
                score += 100
            r_tokens = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]+", r.description.lower()))
            score += len(q_tokens & r_tokens)
            if score > 0:
                scored.append((score, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:k]]


@dataclass
class CannedLLM:
    """
    Deterministic synthesizer used by the eval harness.

    Strategy: pick the top retrieved record, restate its description in one
    sentence, and emit a markdown citation. This is intentionally simple — the
    point is to exercise the citation-integrity contract end-to-end, not to
    benchmark real synthesis quality.
    """

    def synthesize(self, question: str, context: Sequence[CorpusRecord]) -> str:
        if not context:
            return "I cannot answer without retrieved records."
        top = context[0]
        url = top.references[0] if top.references else ""
        if url:
            return f"{top.description} See [{top.cve_id}]({url})."
        return f"{top.description}"


def seed_corpus_from_eval_set() -> list[CorpusRecord]:
    """A minimal corpus aligned with the v0 eval set in eval/researcher_eval_v0.yaml.

    Used by tests and as a smoke fixture. Production runs index the real NVD.
    """
    return [
        CorpusRecord(
            cve_id="CVE-2021-44228",
            description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, enabling remote code execution (Log4Shell).",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        CorpusRecord(
            cve_id="CVE-2021-26855",
            description="Microsoft Exchange Server SSRF (ProxyLogon) enabling unauthenticated remote attackers to bypass authentication and access mailboxes.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
        ),
        CorpusRecord(
            cve_id="CVE-2021-34527",
            description="Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare).",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
        ),
        CorpusRecord(
            cve_id="CVE-2022-26134",
            description="Atlassian Confluence Server and Data Center OGNL injection allowing unauthenticated remote code execution.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
        ),
        CorpusRecord(
            cve_id="CVE-2023-34362",
            description="Progress MOVEit Transfer SQL injection vulnerability exploited by Cl0p ransomware affiliates for mass data theft.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
        ),
        CorpusRecord(
            cve_id="CVE-2023-4966",
            description="Citrix NetScaler ADC and Gateway sensitive information disclosure (Citrix Bleed).",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
        ),
        CorpusRecord(
            cve_id="CVE-2023-46805",
            description="Ivanti Connect Secure and Policy Secure authentication bypass; chained with CVE-2024-21887 for unauthenticated remote code execution.",
            cvss_severity="HIGH",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"],
        ),
        CorpusRecord(
            cve_id="CVE-2024-21887",
            description="Ivanti Connect Secure and Policy Secure command injection vulnerability; chained with CVE-2023-46805 for unauthenticated remote code execution.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21887"],
        ),
        CorpusRecord(
            cve_id="CVE-2022-42475",
            description="Fortinet FortiOS SSL-VPN heap-based buffer overflow allowing unauthenticated remote code execution.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-42475"],
        ),
        CorpusRecord(
            cve_id="CVE-2021-21972",
            description="VMware vCenter Server file upload vulnerability in vRealize Operations vCenter Plugin enabling unauthenticated remote code execution.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"],
        ),
        CorpusRecord(
            cve_id="CVE-2022-1388",
            description="F5 BIG-IP iControl REST authentication bypass enabling root-level command execution.",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
        ),
        CorpusRecord(
            cve_id="CVE-2021-34473",
            description="Microsoft Exchange Server remote code execution (ProxyShell, post-authentication).",
            cvss_severity="CRITICAL",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-34473"],
        ),
    ]


def seed_researcher() -> tuple[Retriever, LanguageModel]:
    corpus = seed_corpus_from_eval_set()
    return CannedRetriever(corpus=corpus), CannedLLM()
