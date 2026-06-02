"""Transparent risk-scoring rubric for AnalyzedFindings.

The proposal commits to *no opaque scoring*. The ranker emits a
``RiskScore`` whose three factors are each individually defensible:

  - **exploitability** (0..1): how plausibly an open service yields an
    attacker capability. Derived from service class (e.g. SMB, RDP, HTTP)
    and whether NSE flagged any CVEs.
  - **asset_criticality** (0..1): operator-supplied; defaults to 0.5 when
    no asset profile is available.
  - **cvss** (0..10): max CVSS of any candidate CVE; falls back to a
    service-class baseline when no CVE is attached.

The composite (``exploitability × asset_criticality × cvss``) determines
rank order but is *never* the only thing surfaced — every score includes a
``reasoning`` string the operator can read.
"""

from __future__ import annotations

from .models import RiskScore

# Coarse exploitability priors keyed by Nmap-reported service name.
# These are deliberately conservative and visible. Tuning is documented; not
# black-box.
SERVICE_EXPLOITABILITY: dict[str, float] = {
    "smb": 0.85,
    "microsoft-ds": 0.85,
    "netbios-ssn": 0.70,
    "rdp": 0.80,
    "ms-wbt-server": 0.80,
    "telnet": 0.90,
    "ftp": 0.60,
    "rlogin": 0.85,
    "rsh": 0.85,
    "vnc": 0.75,
    "redis": 0.70,
    "mongodb": 0.65,
    "elasticsearch": 0.60,
    "memcached": 0.55,
    "http": 0.50,
    "https": 0.50,
    "ssh": 0.30,
    "ldap": 0.55,
    "snmp": 0.50,
    "rpcbind": 0.60,
    "nfs": 0.65,
    "mysql": 0.55,
    "postgresql": 0.50,
    "mssql": 0.65,
    "ms-sql-s": 0.65,
    "dns": 0.30,
    "ntp": 0.20,
}

# Service-class baseline CVSS when no concrete CVE is attached. Calibrated
# against typical NVD severity for the service category.
SERVICE_BASELINE_CVSS: dict[str, float] = {
    "smb": 7.5,
    "microsoft-ds": 7.5,
    "rdp": 7.0,
    "ms-wbt-server": 7.0,
    "telnet": 6.5,
    "ftp": 5.0,
    "rlogin": 6.5,
    "rsh": 6.5,
    "vnc": 6.0,
    "redis": 6.0,
    "mongodb": 5.5,
    "elasticsearch": 5.0,
    "memcached": 4.5,
    "http": 5.0,
    "https": 5.0,
    "ssh": 3.5,
    "ldap": 5.0,
    "snmp": 5.0,
    "rpcbind": 5.5,
    "nfs": 6.0,
    "mysql": 5.0,
    "postgresql": 4.5,
    "mssql": 6.0,
    "ms-sql-s": 6.0,
    "dns": 3.5,
    "ntp": 2.5,
}

UNKNOWN_EXPLOITABILITY_PRIOR = 0.40
UNKNOWN_BASELINE_CVSS = 4.0
CVE_PRESENT_EXPLOITABILITY_FLOOR = 0.60


def score(
    *,
    service: str,
    candidate_cves: list[str],
    cve_cvss_lookup: dict[str, float] | None = None,
    asset_criticality: float = 0.5,
) -> RiskScore:
    """Produce a RiskScore from service evidence and asset context.

    Parameters mirror the rubric inputs verbatim. The returned
    ``RiskScore.reasoning`` records, in plain English, exactly which inputs
    drove which factor.
    """
    svc = (service or "").strip().lower()

    base_exploit = SERVICE_EXPLOITABILITY.get(svc, UNKNOWN_EXPLOITABILITY_PRIOR)
    if candidate_cves:
        exploit = max(base_exploit, CVE_PRESENT_EXPLOITABILITY_FLOOR)
        exploit_reason = (
            f"service={svc or 'unknown'} prior={base_exploit:.2f}; "
            f"raised to {exploit:.2f} because {len(candidate_cves)} candidate CVE(s) attached"
        )
    else:
        exploit = base_exploit
        exploit_reason = (
            f"service={svc or 'unknown'} prior={base_exploit:.2f}; no CVE evidence"
        )

    lookup = cve_cvss_lookup or {}
    cve_scores = [lookup[c] for c in candidate_cves if c in lookup]
    if cve_scores:
        cvss = max(cve_scores)
        cvss_reason = (
            f"max CVSS over {len(cve_scores)} candidate CVE(s) = {cvss:.1f}"
        )
    else:
        cvss = SERVICE_BASELINE_CVSS.get(svc, UNKNOWN_BASELINE_CVSS)
        cvss_reason = (
            f"no CVE lookup hit; using service-class baseline for {svc or 'unknown'} = {cvss:.1f}"
        )

    crit_reason = f"asset_criticality={asset_criticality:.2f} (operator-supplied)"
    reasoning = " | ".join([exploit_reason, crit_reason, cvss_reason])

    return RiskScore(
        exploitability=exploit,
        asset_criticality=asset_criticality,
        cvss=cvss,
        reasoning=reasoning,
    )
