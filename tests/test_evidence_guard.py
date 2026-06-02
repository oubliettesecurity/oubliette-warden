"""Tests for the citation-bound evidence guard (B7).

Covers rules R1..R5 from ``evidence_guard.IntegrityGuard``:

  R1. >=1 citation
  R2. mentioned CVE ids must be in retrieved set
  R3. citation URL prefix in accepted list
  R4. citation URL in retrieved references
  R5. citation cve_id in retrieved set

Plus the optional corroboration rule.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.evidence_guard import (  # noqa: E402
    ACCEPTED_SOURCE_PREFIXES,
    Citation,
    CorpusRecord,
    IntegrityGuard,
)


NVD_URL_A = "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
NVD_URL_B = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
MSRC_URL = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"
HALLUCINATED_URL = "https://example.com/totally-made-up-cve"


def _records():
    return [
        CorpusRecord(
            cve_id="CVE-2017-0144",
            description="EternalBlue SMB RCE",
            cvss_severity="HIGH",
            references=[NVD_URL_A, MSRC_URL],
        ),
        CorpusRecord(
            cve_id="CVE-2021-44228",
            description="Log4Shell JNDI RCE",
            cvss_severity="CRITICAL",
            references=[NVD_URL_B],
        ),
    ]


# ---------- accepted-source allowlist sanity ----------


def test_default_prefix_set_is_nonempty():
    assert ACCEPTED_SOURCE_PREFIXES
    assert any(p.startswith("https://nvd.nist.gov") for p in ACCEPTED_SOURCE_PREFIXES)


# ---------- R1: at least one citation ----------


def test_R1_no_citations_rejected():
    g = IntegrityGuard()
    report = g.check("Use SMB hardening to mitigate.", _records(), citations=[])
    assert not report.accepted
    assert any("no citations" in r for r in report.rejected_reasons)


# ---------- R2: mentioned CVE must be retrieved ----------


def test_R2_unsupported_cve_in_answer_rejected():
    g = IntegrityGuard()
    text = "Affected by CVE-2099-0001 and CVE-2017-0144."
    report = g.check(
        text,
        _records(),
        citations=[Citation(cve_id="CVE-2017-0144", url=NVD_URL_A)],
    )
    assert not report.accepted
    assert any("CVE-2099-0001" in r for r in report.rejected_reasons)


# ---------- R3: URL must be on accepted-prefix list ----------


def test_R3_off_allowlist_url_rejected():
    g = IntegrityGuard()
    bad_cit = Citation(cve_id="CVE-2017-0144", url=HALLUCINATED_URL)
    report = g.check("See [CVE-2017-0144](" + HALLUCINATED_URL + ").", _records(), [bad_cit])
    assert not report.accepted
    assert any("accepted source prefixes" in r for r in report.rejected_reasons)


def test_R3_can_be_relaxed_via_constructor():
    """Pass an explicit prefix set to whitelist a fixture URL for tests."""
    g = IntegrityGuard(accepted_prefixes=["https://example.com/"])
    # also adjust the retrieved record to include the URL so R4 passes
    rec = CorpusRecord(
        cve_id="CVE-2017-0144",
        description="x",
        cvss_severity="HIGH",
        references=[HALLUCINATED_URL],
    )
    cit = Citation(cve_id="CVE-2017-0144", url=HALLUCINATED_URL)
    report = g.check("see CVE-2017-0144 (" + HALLUCINATED_URL + ")", [rec], [cit])
    assert report.accepted, report.rejected_reasons


# ---------- R4: URL must appear in retrieved record references ----------


def test_R4_url_not_in_retrieved_references_rejected():
    g = IntegrityGuard()
    cit = Citation(
        cve_id="CVE-2017-0144",
        url="https://nvd.nist.gov/vuln/detail/CVE-2017-9999",  # not in references
    )
    report = g.check("see CVE-2017-0144 (" + cit.url + ")", _records(), [cit])
    assert not report.accepted
    assert any("not in corpus references" in r for r in report.rejected_reasons)


# ---------- R5: citation cve_id must be retrieved ----------


def test_R5_citation_cve_not_retrieved_rejected():
    g = IntegrityGuard()
    cit = Citation(cve_id="CVE-2099-0001", url=NVD_URL_A)
    report = g.check("see CVE-2099-0001 (" + NVD_URL_A + ")", _records(), [cit])
    assert not report.accepted
    assert any("citation cve_id not retrieved" in r for r in report.rejected_reasons)


# ---------- happy path ----------


def test_well_formed_answer_accepted():
    g = IntegrityGuard()
    text = (
        "EternalBlue affects SMBv1 — mitigated by disabling SMBv1 "
        "(see [CVE-2017-0144](" + NVD_URL_A + "))."
    )
    cit = Citation(cve_id="CVE-2017-0144", url=NVD_URL_A)
    report = g.check(text, _records(), [cit])
    assert report.accepted, report.rejected_reasons
    assert "R1..R5 satisfied" in " | ".join(report.audit_trail)


# ---------- malformed citation ----------


def test_malformed_citation_rejected():
    g = IntegrityGuard()
    bad = Citation(cve_id="not-a-cve", url="ftp://server/x")  # both fields bad
    report = g.check("text", _records(), [bad])
    assert not report.accepted
    assert any("malformed citation" in r for r in report.rejected_reasons)


# ---------- corroboration option ----------


def test_corroboration_requires_two_distinct_sources():
    g = IntegrityGuard(require_corroboration=True)
    # Only NVD-sourced — should fail corroboration even though everything else
    # is well-formed.
    cit = Citation(cve_id="CVE-2017-0144", url=NVD_URL_A)
    report = g.check(
        "see [CVE-2017-0144](" + NVD_URL_A + ")",
        _records(),
        [cit],
    )
    assert not report.accepted
    assert any("corroboration" in r for r in report.rejected_reasons)


def test_corroboration_passes_with_two_sources():
    g = IntegrityGuard(require_corroboration=True)
    cit_a = Citation(cve_id="CVE-2017-0144", url=NVD_URL_A)
    cit_b = Citation(cve_id="CVE-2017-0144", url=MSRC_URL)
    text = (
        "see [CVE-2017-0144](" + NVD_URL_A + ") and "
        "[CVE-2017-0144](" + MSRC_URL + ")"
    )
    report = g.check(text, _records(), [cit_a, cit_b])
    assert report.accepted, report.rejected_reasons


# ---------- audit-log binding ----------


def test_audit_trail_present_on_accept_and_reject():
    g = IntegrityGuard()
    accept = g.check(
        "see [CVE-2017-0144](" + NVD_URL_A + ")",
        _records(),
        [Citation(cve_id="CVE-2017-0144", url=NVD_URL_A)],
    )
    assert accept.audit_trail
    assert accept.explain().startswith("evidence guard: accepted")

    reject = g.check("uncited claim about CVE-2099-0001", _records(), citations=[])
    assert reject.rejected_reasons
    assert reject.explain().startswith("evidence guard: rejected")
