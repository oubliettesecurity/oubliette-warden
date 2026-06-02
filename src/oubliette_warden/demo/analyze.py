"""Shot 5 of the screencast — Cyber Analysis agent ranks findings.

Usage:
    python -m oubliette_warden.demo.analyze [PATH_TO_NMAP_XML]
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..agents.analysis.analyst import CyberAnalyst


# A minimal CALDERA-fixture Nmap XML so the demo runs without a real scan.
_FIXTURE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.50.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows SMB"/>
        <script id="vulners" output="CVE-2017-0144"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.50.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH 8.2"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.50.0.30" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_CVE_LOOKUP: dict[str, float] = {"CVE-2017-0144": 8.1}


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if args and args[0]:
        xml = Path(args[0]).read_text(encoding="utf-8")
        src = args[0]
    else:
        xml = _FIXTURE_XML
        src = "(built-in CALDERA fixture)"

    analyst = CyberAnalyst()
    findings = analyst.analyze_nmap_xml(xml, cve_cvss_lookup=_CVE_LOOKUP)

    print(f"source: {src}")
    print(f"findings: {len(findings)} ranked")
    print("-" * 60)
    for idx, f in enumerate(findings, start=1):
        cves = ",".join(f.candidate_cves) or "—"
        print(
            f"  {idx}. {f.service_summary:<40}  composite={f.risk.composite:>5.2f}"
            f"   CVE={cves}"
        )
    print("-" * 60)
    if findings:
        top = findings[0]
        print(f"top finding reasoning chain:")
        for step in top.reasoning_chain:
            print(f"  · {step}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
