"""Citation-bound evidence guard for the Vulnerability Research agent.

This module is the Oubliette Warden port of the sift-guard ``EvidenceGuard`` pattern
from `oubliette-shield/find-evil/src/guard/evidence_guard.py`. sift-guard's
guard enforces evidence integrity at the *forensic-artifact* layer
(read-only paths, hive allowlists, destructive-command blocks). Oubliette Warden's
guard enforces the same pattern at the *vulnerability-record* layer:

  - Source allowlist: only records from accepted corpora may be cited
  - Fail-closed default: any unproven claim is rejected before it leaves
    the agent
  - Audit-log binding: every rejection records its reason in a structured
    ``IntegrityReport`` the operator (and any later replay) can read

The behavioral contract is identical in spirit to sift-guard's: the guard
*defends* the agent's output, never trusts it. ``IntegrityGuard`` below is
re-exported by ``researcher.py`` for backward compatibility with the
existing test suite, but the canonical home is this module.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

# CVE identifier shape per https://cve.mitre.org/cve/identifiers/syntaxchange.html.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def canonical_nvd_url(cve_id: str) -> str:
    """The authoritative NVD detail page for a CVE.

    Every record in the Oubliette Warden corpus was sourced from NVD, so the NVD
    detail page is always a valid citation for a retrieved CVE — even when
    that exact URL isn't among the record's vendor-advisory references.
    """
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

# Accepted citation-URL prefixes. The Phase I corpus is NIST NVD + CISA
# KEV + first-party vendor advisories that NVD redirects to. Anything
# outside these prefixes is treated as a hallucinated source URL.
ACCEPTED_SOURCE_PREFIXES: frozenset[str] = frozenset({
    "https://nvd.nist.gov/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://www.cisa.gov/news-events/cybersecurity-advisories",
    "https://cve.mitre.org/",
    "https://www.cve.org/",
    "https://attack.mitre.org/",
    "https://capec.mitre.org/",
    "https://cwe.mitre.org/",
    "https://msrc.microsoft.com/",
    "https://access.redhat.com/security/cve/",
    "https://lists.debian.org/debian-security-announce/",
    "https://ubuntu.com/security/notices/",
    "https://www.debian.org/security/",
    "https://www.openssl.org/news/secadv/",
    "https://www.apache.org/security/",
})


# ----- public types ----------------------------------------------------------


@dataclass(frozen=True)
class CorpusRecord:
    """A retrievable vulnerability record (NVD-shaped).

    Re-exported by ``researcher.py`` for backward compatibility.
    """

    cve_id: str
    description: str
    cvss_severity: str | None
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Citation:
    """A pointer from an answer back to a corpus record."""

    cve_id: str
    url: str

    def is_well_formed(self) -> bool:
        return bool(CVE_RE.fullmatch(self.cve_id)) and self.url.startswith(
            ("http://", "https://")
        )


@dataclass
class IntegrityReport:
    """Structured guard verdict — drives the audit log."""

    accepted: bool
    rejected_reasons: list[str] = field(default_factory=list)
    audit_trail: list[str] = field(default_factory=list)

    def explain(self) -> str:
        if self.accepted:
            return "evidence guard: accepted — " + "; ".join(self.audit_trail)
        return "evidence guard: rejected — " + "; ".join(self.rejected_reasons)


# ----- the guard -------------------------------------------------------------


class IntegrityGuard:
    """Fail-closed citation-integrity enforcement.

    Rejection rules — every accepted answer must satisfy all of:

      R1. Answer cites at least one retrieved corpus record
      R2. Every claimed CVE id in the answer text is a retrieved CVE id
      R3. Every citation's URL belongs to ``ACCEPTED_SOURCE_PREFIXES``
      R4. Every citation's URL appears in the retrieved record's references
      R5. Every citation's CVE id is one of the retrieved record CVE ids

    The default is **reject**: if no rule has fired but no rule has affirmed
    either, the answer is rejected. This mirrors sift-guard's evidence-dir
    enforcement, where ambiguous paths are denied rather than allowed.
    """

    def __init__(
        self,
        *,
        accepted_prefixes: Iterable[str] | None = None,
        require_corroboration: bool = False,
    ) -> None:
        self._accepted_prefixes = (
            tuple(accepted_prefixes)
            if accepted_prefixes is not None
            else tuple(ACCEPTED_SOURCE_PREFIXES)
        )
        self._require_corroboration = require_corroboration

    def check(
        self,
        answer_text: str,
        retrieved: Iterable[CorpusRecord],
        citations: Sequence[Citation],
    ) -> IntegrityReport:
        retrieved_list = list(retrieved)
        retrieved_ids = {r.cve_id for r in retrieved_list}
        retrieved_urls = {u for r in retrieved_list for u in r.references}
        # The canonical NVD detail page is always a valid citation target
        # for a retrieved CVE — the whole corpus is NVD-sourced.
        retrieved_urls |= {canonical_nvd_url(r.cve_id) for r in retrieved_list}
        mentioned = set(CVE_RE.findall(answer_text))

        reasons: list[str] = []
        trail: list[str] = []

        trail.append(f"retrieved {len(retrieved_list)} record(s)")
        trail.append(f"answer text mentions {len(mentioned)} CVE id(s)")
        trail.append(f"answer offers {len(citations)} citation(s)")

        # R2 — every mentioned CVE must be retrieved
        unsupported = mentioned - retrieved_ids
        if unsupported:
            reasons.append(
                f"answer mentions unsupported CVE ids: {sorted(unsupported)}"
            )

        # R1 — at least one citation
        if not citations:
            reasons.append("answer has no citations (R1)")

        # R3 / R4 / R5 — per-citation checks
        for c in citations:
            if not c.is_well_formed():
                reasons.append(f"malformed citation: {c}")
                continue
            if not c.url.startswith(self._accepted_prefixes):
                reasons.append(
                    f"citation url not in accepted source prefixes (R3): {c.url}"
                )
            if c.cve_id not in retrieved_ids:
                reasons.append(f"citation cve_id not retrieved (R5): {c.cve_id}")
            if c.url not in retrieved_urls:
                reasons.append(
                    f"citation url not in corpus references (R4): {c.url}"
                )

        # Optional: require >=2 *distinct* sources backing the answer.
        if self._require_corroboration and not reasons:
            distinct_sources = {_source_of(c.url) for c in citations}
            if len(distinct_sources) < 2:
                reasons.append(
                    "corroboration required: at least 2 distinct sources expected"
                )

        accepted = not reasons
        if accepted:
            trail.append("all rules R1..R5 satisfied")
        return IntegrityReport(
            accepted=accepted,
            rejected_reasons=reasons,
            audit_trail=trail,
        )


# ----- helpers ---------------------------------------------------------------


def _source_of(url: str) -> str:
    """Coarse source key for corroboration: the host of the URL."""
    # Avoid urllib.parse import overhead; a regex is enough for http(s).
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else url
