"""Nmap XML → flat per-(host, port) observation list.

The Cyber Analysis agent consumes *raw* tool output by contract (§2 Obj 4),
so it cannot assume the CodeGen adapter has already pre-parsed for it.

We deliberately re-implement parsing here rather than importing
``NmapAdapter._parse_xml``: the analyst must be able to ingest XML that came
from a saved scan, a CALDERA-replayed exercise, or any other source — not
just a freshly-run adapter call.

The output shape is a list of ``PortObservation`` records (one per open
port), with NSE-script-derived CVE candidates surfaced as a list. ATT&CK
technique tagging is applied at this layer based on service class.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Service-class → ATT&CK technique tags. Conservative; extend as the
# scenario library grows.
SERVICE_ATTCK_TAGS: dict[str, list[str]] = {
    "smb": ["T1021.002", "T1135"],
    "microsoft-ds": ["T1021.002", "T1135"],
    "netbios-ssn": ["T1021.002", "T1135"],
    "rdp": ["T1021.001"],
    "ms-wbt-server": ["T1021.001"],
    "ssh": ["T1021.004"],
    "telnet": ["T1021"],
    "ftp": ["T1071.002"],
    "http": ["T1071.001"],
    "https": ["T1071.001"],
    "dns": ["T1071.004"],
    "ldap": ["T1087.002"],
    "snmp": ["T1046"],
    "vnc": ["T1021.005"],
    "mysql": ["T1505.003"],
    "postgresql": ["T1505.003"],
    "mssql": ["T1505.003"],
    "ms-sql-s": ["T1505.003"],
    "redis": ["T1505"],
    "mongodb": ["T1505"],
}


@dataclass(frozen=True)
class PortObservation:
    """One open-port row pulled from Nmap XML."""

    host_address: str
    port: int
    protocol: str
    service: str
    product: str
    state: str
    candidate_cves: list[str] = field(default_factory=list)
    attck_technique_ids: list[str] = field(default_factory=list)


class NmapXMLParseError(ValueError):
    """Raised when input XML is unparseable. Empty input is *not* an error."""


def parse_nmap_xml(xml_text: str) -> list[PortObservation]:
    """Return one PortObservation per open port across all hosts in the report."""
    if not xml_text or not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapXMLParseError(str(exc)) from exc

    out: list[PortObservation] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        address = addr_el.get("addr", "")
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            try:
                portid = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            proto = port_el.get("protocol", "")

            svc_el = port_el.find("service")
            service = (svc_el.get("name", "") if svc_el is not None else "").lower()
            product = svc_el.get("product", "") if svc_el is not None else ""

            cves: set[str] = set()
            for script_el in port_el.findall("script"):
                out_text = script_el.get("output", "") or ""
                cves.update(CVE_RE.findall(out_text))

            tags = SERVICE_ATTCK_TAGS.get(service, [])

            out.append(
                PortObservation(
                    host_address=address,
                    port=portid,
                    protocol=proto,
                    service=service,
                    product=product,
                    state="open",
                    candidate_cves=sorted(cves),
                    attck_technique_ids=list(tags),
                )
            )
    return out
