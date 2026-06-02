"""Data models for the Cyber Analysis agent.

The Analyst's job is to take heterogeneous tool output (Nmap XML today; Nessus
JSON and MSF auxiliary results in Phase II) and produce a *ranked* list of
findings that an operator can act on. Every Finding carries its own reasoning
chain so the rank is auditable — no opaque "top-10."

The shape of ``AnalyzedFinding`` is intentionally richer than the bare
``Finding`` emitted by a CommandAdapter: it adds ATT&CK technique tags,
candidate CVEs, a transparent ``RiskScore`` with three named factors, and an
operator-readable one-paragraph summary.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AssetProfile:
    """Operator-supplied context about a target asset.

    Phase I accepts a flat dict-equivalent. Phase II will load profiles from a
    customer-furnished asset model.
    """

    address: str
    criticality: float = 0.5  # 0.0 (sandbox) .. 1.0 (mission-critical)
    role: str = "unknown"
    notes: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError(
                f"criticality must be in [0,1], got {self.criticality!r}"
            )


@dataclass(frozen=True)
class RiskScore:
    """Transparent three-factor rubric: exploitability × asset criticality × cvss.

    The Analyst never emits a score without the three components that produced
    it. ``reasoning`` is the human-readable explanation captured in the audit
    log.
    """

    exploitability: float  # 0.0 .. 1.0
    asset_criticality: float  # 0.0 .. 1.0
    cvss: float  # 0.0 .. 10.0 (NVD convention)
    reasoning: str

    def __post_init__(self) -> None:
        for name, val, hi in (
            ("exploitability", self.exploitability, 1.0),
            ("asset_criticality", self.asset_criticality, 1.0),
            ("cvss", self.cvss, 10.0),
        ):
            if not 0.0 <= val <= hi:
                raise ValueError(f"{name} out of [0,{hi}]: {val!r}")

    @property
    def composite(self) -> float:
        """Composite score on a 0..10 scale, monotone in all three factors."""
        return self.exploitability * self.asset_criticality * self.cvss


@dataclass(frozen=True)
class AnalyzedFinding:
    """One ranked finding the operator reviews.

    The audit log captures everything in this record verbatim so workflow
    replay can reproduce the ranking without re-executing tools.
    """

    finding_id: str
    asset_address: str
    service_summary: str
    attck_technique_ids: list[str]
    candidate_cves: list[str]
    risk: RiskScore
    operator_summary: str
    source_adapter: str
    reasoning_chain: list[str] = field(default_factory=list)
