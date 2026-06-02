"""Cyber Analysis agent — the §2 Objective 4 deliverable.

Given heterogeneous scanner output (Phase I: Nmap XML), produce a ranked list
of ``AnalyzedFinding`` records. Every finding carries:

  - Its source adapter
  - ATT&CK technique tags inferred from the service class
  - Candidate CVEs forwarded to the Vulnerability Research agent
  - A transparent ``RiskScore`` (exploitability × asset_criticality × cvss)
  - A one-paragraph operator-readable summary
  - A reasoning chain captured for the audit log (no opaque ranking)

The acceptance criterion is ≤90 s on a 254-host CALDERA range; the
implementation is pure Python with no I/O on the analysis path, so the
budget is governed entirely by ``parse_nmap_xml`` and trivial arithmetic.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping

from .models import AnalyzedFinding, AssetProfile, RiskScore
from .nmap_ingest import PortObservation, parse_nmap_xml
from .ranker import score


class CyberAnalyst:
    """Ingest → normalize → rank pipeline for the Cyber Analysis agent."""

    def __init__(
        self,
        *,
        id_factory=None,
        default_asset_criticality: float = 0.5,
    ) -> None:
        self._mint_id = id_factory or (lambda: f"af-{uuid.uuid4().hex[:8]}")
        self._default_crit = default_asset_criticality

    def analyze_nmap_xml(
        self,
        xml_text: str,
        *,
        asset_profiles: Mapping[str, AssetProfile] | None = None,
        cve_cvss_lookup: Mapping[str, float] | None = None,
    ) -> list[AnalyzedFinding]:
        """Top-level entry point: XML in, ranked findings out."""
        observations = parse_nmap_xml(xml_text)
        return self._rank_observations(
            observations,
            asset_profiles=asset_profiles or {},
            cve_cvss_lookup=cve_cvss_lookup or {},
        )

    def _rank_observations(
        self,
        observations: Iterable[PortObservation],
        *,
        asset_profiles: Mapping[str, AssetProfile],
        cve_cvss_lookup: Mapping[str, float],
    ) -> list[AnalyzedFinding]:
        findings: list[AnalyzedFinding] = []
        for obs in observations:
            asset = asset_profiles.get(obs.host_address)
            criticality = asset.criticality if asset else self._default_crit

            risk = score(
                service=obs.service,
                candidate_cves=obs.candidate_cves,
                cve_cvss_lookup=dict(cve_cvss_lookup),
                asset_criticality=criticality,
            )

            findings.append(
                AnalyzedFinding(
                    finding_id=self._mint_id(),
                    asset_address=obs.host_address,
                    service_summary=_describe_port(obs),
                    attck_technique_ids=list(obs.attck_technique_ids),
                    candidate_cves=list(obs.candidate_cves),
                    risk=risk,
                    operator_summary=_operator_summary(obs, risk, asset),
                    source_adapter="nmap",
                    reasoning_chain=_reasoning_chain(obs, risk, asset),
                )
            )

        # Sort by composite score, then by host address + port for stable order.
        findings.sort(
            key=lambda f: (-f.risk.composite, f.asset_address, f.service_summary)
        )
        # Append rank-position to each reasoning chain so the audit log can
        # answer "why is this in position N" without re-sorting.
        ranked: list[AnalyzedFinding] = []
        total = len(findings)
        for idx, f in enumerate(findings, start=1):
            ranked.append(
                AnalyzedFinding(
                    finding_id=f.finding_id,
                    asset_address=f.asset_address,
                    service_summary=f.service_summary,
                    attck_technique_ids=f.attck_technique_ids,
                    candidate_cves=f.candidate_cves,
                    risk=f.risk,
                    operator_summary=f.operator_summary,
                    source_adapter=f.source_adapter,
                    reasoning_chain=[
                        *f.reasoning_chain,
                        f"ranked {idx}/{total} by composite={f.risk.composite:.2f}",
                    ],
                )
            )
        return ranked


def _describe_port(obs: PortObservation) -> str:
    parts = [f"{obs.host_address}:{obs.port}/{obs.protocol}"]
    if obs.service:
        parts.append(obs.service)
    if obs.product:
        parts.append(f"({obs.product})")
    return " ".join(parts)


def _operator_summary(
    obs: PortObservation, risk: RiskScore, asset: AssetProfile | None
) -> str:
    role = asset.role if asset else "unprofiled"
    cve_note = (
        f"{len(obs.candidate_cves)} candidate CVE(s) flagged by NSE"
        if obs.candidate_cves
        else "no CVE evidence yet"
    )
    return (
        f"{obs.service or 'unknown service'} exposed on {obs.host_address}:{obs.port}"
        f" ({role} asset). Composite risk {risk.composite:.2f}: "
        f"exploitability {risk.exploitability:.2f} × criticality "
        f"{risk.asset_criticality:.2f} × CVSS {risk.cvss:.1f}. {cve_note}."
    )


def _reasoning_chain(
    obs: PortObservation, risk: RiskScore, asset: AssetProfile | None
) -> list[str]:
    chain = [
        f"observed open port {obs.host_address}:{obs.port}/{obs.protocol}"
        f" (service={obs.service or 'unknown'}, product={obs.product or 'n/a'})",
    ]
    if obs.attck_technique_ids:
        chain.append(
            f"tagged ATT&CK techniques {obs.attck_technique_ids} from service class"
        )
    if asset is None:
        chain.append("no asset profile available; using default criticality")
    else:
        chain.append(
            f"asset profile applied: role={asset.role}, criticality={asset.criticality:.2f}"
        )
    chain.append(f"risk score derived: {risk.reasoning}")
    chain.append(f"composite = {risk.composite:.2f}")
    return chain
