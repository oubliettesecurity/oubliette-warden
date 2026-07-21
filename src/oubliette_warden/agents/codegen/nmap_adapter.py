"""
Nmap CommandAdapter for the Oubliette Warden Code Generation & Execution agent.

Phase I scope: enumeration only. The adapter never emits a command that
modifies the target (no -sN with --reason interpretation as actionable,
no NSE scripts categorized as 'intrusive', 'exploit', or 'dos').

Output: Nmap XML, parsed into a Finding with host/port/service tuples and
ATT&CK Reconnaissance/Discovery tactic tagging. CVE candidates surfaced
by the NSE 'vulners' script are forwarded to the Researcher agent.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from oubliette_warden.operator_ui.review_queue import ReviewQueue

from .base import (
    AttackTechnique,
    Command,
    CommandAdapter,
    ExecutionEnv,
    Finding,
    Task,
)

PROHIBITED_NSE_CATEGORIES = frozenset({"intrusive", "exploit", "dos", "brute"})
# Allow-list of NSE categories/scripts Phase I may emit. This is an ALLOW-list:
# any --script token outside this set is refused. "vulners" is the specific
# read-only CVE-lookup script the adapter itself emits for vuln-intent scans.
ALLOWED_NSE_CATEGORIES = frozenset(
    {"safe", "default", "discovery", "version", "vuln", "vulners"}
)

CIDR_RE = re.compile(r"^[0-9A-Fa-f:.]+/\d{1,3}$")
HOST_RE = re.compile(r"^[0-9A-Fa-f:.]+$|^[A-Za-z0-9.\-]+$")


class NmapTargetError(ValueError):
    """Raised when target syntax is rejected before command emission."""


class NmapPolicyError(RuntimeError):
    """Raised when the adapter is asked to do something Phase I forbids."""


class NmapAdapter(CommandAdapter):
    name = "nmap"
    version = "phase1.0"

    def __init__(
        self,
        binary: str = "nmap",
        timeout_seconds: int = 600,
        scratch_dir: Path | None = None,
        review_queue: "ReviewQueue | None" = None,
    ) -> None:
        self._binary = binary
        self._timeout = timeout_seconds
        self._scratch = scratch_dir or Path(tempfile.gettempdir()) / "oubliette_warden_nmap"
        self._scratch.mkdir(parents=True, exist_ok=True)
        self._review_queue = review_queue

    # ---------- adapter contract ----------

    def is_available(self) -> bool:
        return shutil.which(self._binary) is not None

    def plan(self, task: Task) -> Command:
        targets = self._validate_targets(task.target_scope)
        intent = task.intent.lower()

        if "vuln" in intent:
            scripts = "default,vuln,vulners"
            attck_ids = ["T1595.002", "T1046"]
            tactics = [AttackTechnique.RECONNAISSANCE, AttackTechnique.DISCOVERY]
        elif "service" in intent or "version" in intent:
            scripts = "default"
            attck_ids = ["T1046"]
            tactics = [AttackTechnique.DISCOVERY]
        else:
            scripts = "default"
            attck_ids = ["T1595.001", "T1018"]
            tactics = [AttackTechnique.RECONNAISSANCE, AttackTechnique.DISCOVERY]

        argv = [
            self._binary,
            "-sV",
            "-sC",
            "--script", scripts,
            "-oX", "-",
            "--max-retries", "2",
            "--host-timeout", "120s",
            *targets,
        ]
        return Command(
            adapter_name=self.name,
            argv=argv,
            target_scope=targets,
            attck_tactics=tactics,
            attck_technique_ids=attck_ids,
            is_active_probe=True,
            expected_runtime_seconds=min(self._timeout, 300),
            rationale=f"Phase I enumeration: intent={task.intent!r} scope={targets}",
            task_id=task.task_id,
        )

    def execute(self, command: Command, env: ExecutionEnv) -> Finding:
        self._enforce_phase1_policy(command, env)
        # The advertised five-stage safety gate is authoritative: refuse to
        # execute unless it APPROVEs (ESCALATE requires operator sign-off).
        self._gate_or_raise(command, env, NmapPolicyError)
        if not self.is_available():
            raise NmapPolicyError("nmap binary not available on this host")

        proc = subprocess.run(
            command.argv,
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )
        xml_path = self._scratch_path(command.argv)
        xml_path.write_text(proc.stdout, encoding="utf-8")
        parsed = self._parse_xml(proc.stdout)
        cves = sorted({c for h in parsed.get("hosts", []) for c in h.get("cves", [])})
        return Finding(
            adapter_name=self.name,
            task_id=parsed.get("task_id", ""),
            summary=self._summarize(parsed, proc.returncode),
            raw_output_path=str(xml_path),
            parsed=parsed,
            attck_technique_ids=command.attck_technique_ids,
            candidate_cves=cves,
        )

    # ---------- helpers (unit-tested) ----------

    def _scratch_path(self, argv: list[str]) -> Path:
        """Unique XML scratch path per invocation.

        A hash of argv alone collides for identical scans, clobbering the
        previous run's raw output and corrupting the audit/replay trail. A
        uuid4 suffix guarantees each invocation keeps its own artifact.
        """
        return self._scratch / f"nmap_{uuid.uuid4().hex}.xml"

    @staticmethod
    def _validate_targets(scope: list[str]) -> list[str]:
        if not scope:
            raise NmapTargetError("empty target scope")
        out: list[str] = []
        for raw in scope:
            t = raw.strip()
            if not t:
                continue
            # A token starting with '-' would be parsed by nmap as an option,
            # not a target — e.g. a crafted "--script" target could inject a
            # second NSE selector into argv. Reject before it reaches argv.
            if t.startswith("-"):
                raise NmapTargetError(f"target may not start with '-': {t!r}")
            if CIDR_RE.match(t):
                try:
                    ipaddress.ip_network(t, strict=False)
                except ValueError as e:
                    raise NmapTargetError(f"invalid CIDR: {t}") from e
                out.append(t)
            elif HOST_RE.match(t):
                out.append(t)
            else:
                raise NmapTargetError(f"target syntax rejected: {t!r}")
        if not out:
            raise NmapTargetError("no valid targets after validation")
        return out

    @staticmethod
    def _enforce_phase1_policy(command: Command, env: ExecutionEnv) -> None:
        if env != ExecutionEnv.CALDERA_ONLY:
            raise NmapPolicyError(
                f"Phase I builds enforce CALDERA_ONLY execution; got {env}"
            )
        if command.is_impact_class():
            raise NmapPolicyError("Impact-tactic commands are not permitted in Phase I")
        # Inspect EVERY --script occurrence (not just the first) and enforce
        # ALLOWED_NSE_CATEGORIES as an allow-list: anything not explicitly
        # permitted is rejected, so categories like fuzzer/malware/external/
        # auth/broadcast can never slip through.
        argv = command.argv
        for idx, tok in enumerate(argv):
            if tok != "--script":
                continue
            scripts = argv[idx + 1] if idx + 1 < len(argv) else ""
            for raw_cat in scripts.split(","):
                cat = raw_cat.strip().lower()
                if not cat:
                    continue
                if cat in PROHIBITED_NSE_CATEGORIES:
                    raise NmapPolicyError(
                        f"NSE category {cat!r} is prohibited in Phase I"
                    )
                if cat not in ALLOWED_NSE_CATEGORIES:
                    raise NmapPolicyError(
                        f"NSE category {cat!r} is not in the Phase I allow-list"
                    )

    @staticmethod
    def _parse_xml(xml_text: str) -> dict[str, Any]:
        if not xml_text.strip():
            return {"hosts": []}
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return {"hosts": [], "parse_error": True}
        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ports_el = host.find("ports")
            ports: list[dict[str, Any]] = []
            cves: set[str] = set()
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    portid = port.get("portid", "")
                    proto = port.get("protocol", "")
                    state_el = port.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    svc_el = port.find("service")
                    service = svc_el.get("name", "") if svc_el is not None else ""
                    product = svc_el.get("product", "") if svc_el is not None else ""
                    for script in port.findall("script"):
                        out = script.get("output", "") or ""
                        for m in re.finditer(r"CVE-\d{4}-\d{4,7}", out):
                            cves.add(m.group(0))
                    ports.append(
                        {
                            "portid": portid,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "product": product,
                        }
                    )
            hosts.append({"address": addr_el.get("addr", ""), "ports": ports, "cves": sorted(cves)})
        return {"hosts": hosts}

    @staticmethod
    def _summarize(parsed: dict[str, Any], returncode: int) -> str:
        n_hosts = len(parsed.get("hosts", []))
        n_open = sum(
            1
            for h in parsed.get("hosts", [])
            for p in h.get("ports", [])
            if p.get("state") == "open"
        )
        rc_note = "" if returncode == 0 else f" (nmap rc={returncode})"
        return f"{n_hosts} hosts scanned, {n_open} open ports observed{rc_note}"
