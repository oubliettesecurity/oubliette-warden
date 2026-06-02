"""Metasploit Framework auxiliary-module CommandAdapter for the CodeGen agent.

Phase I scope is **auxiliary scanner modules only**. The adapter NEVER emits:

  - exploit/* modules
  - post/* modules
  - payload/* modules
  - encoder/* modules
  - any module whose options mutate state on the target

Auxiliary modules are MSF's read-only equivalents of Nmap NSE scripts:
service-detection, weak-credential checks, anonymous-access probes, etc.

The adapter speaks to ``msfrpcd`` (MSF JSON-RPC service) by default. For
unit tests the RPC client is injected, so no daemon is required to verify
the emit-and-gate contract.

Output: a structured ``Finding`` with ``parsed`` carrying the auxiliary
module's JSON result rows; CVE candidates surfaced from module metadata
are forwarded to the Cyber Analysis and Vulnerability Research agents.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Protocol

from .base import (
    AttackTechnique,
    Command,
    CommandAdapter,
    ExecutionEnv,
    Finding,
    Task,
)

PERMITTED_MODULE_PREFIX = "auxiliary/scanner/"

# Allow-list of auxiliary-scanner subcategories Phase I can emit. Anything
# outside this set is rejected before a Command is built. Broad scanner
# coverage but explicitly read-only categories only.
ALLOWED_SCANNER_CATEGORIES = frozenset({
    "smb",
    "smtp",
    "snmp",
    "ssh",
    "telnet",
    "ftp",
    "http",
    "vnc",
    "rdp",
    "discovery",
    "portscan",
    "netbios",
    "mysql",
    "postgres",
    "mssql",
    "oracle",
    "rsync",
    "dns",
    "ntp",
})

# Hard-deny: even if a path begins with auxiliary/scanner/, these names
# encode active-state-change behavior and are forbidden in Phase I.
PROHIBITED_NAME_FRAGMENTS = frozenset({
    "login",        # brute / spray
    "brute",
    "force",
    "_dos",
    "exploit",
    "payload",
})

MODULE_RE = re.compile(r"^[a-z0-9_/]+$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class MSFTargetError(ValueError):
    """Target syntax rejected before command emission."""


class MSFPolicyError(RuntimeError):
    """The adapter was asked to do something Phase I forbids."""


class MSFRPCClient(Protocol):
    """Minimal contract for an injectable msfrpcd client.

    The real client wraps the JSON-RPC endpoint; tests supply a fake. We do
    not depend on a specific pypi msfrpc binding so the codepath stays
    portable.
    """

    def module_info(self, module: str) -> dict[str, Any]: ...
    def module_run(self, module: str, options: dict[str, Any]) -> dict[str, Any]: ...


class MSFAuxAdapter(CommandAdapter):
    """Read-only Metasploit auxiliary-scanner adapter."""

    name = "msf-aux"
    version = "phase1.0"

    def __init__(
        self,
        client: MSFRPCClient | None = None,
        default_module: str = "auxiliary/scanner/portscan/tcp",
    ) -> None:
        self._client = client
        self._default_module = default_module
        self._validate_module(default_module)

    # ---------- adapter contract ----------

    def is_available(self) -> bool:
        return self._client is not None

    def plan(self, task: Task) -> Command:
        targets = self._validate_targets(task.target_scope)
        intent = task.intent.lower()
        module = self._select_module(intent)

        # Build an argv-shaped command even though MSF is invoked via RPC.
        # argv-form keeps the safety gate's static inspection contract
        # consistent across adapters (the gate doesn't care that the
        # "execution" is RPC; it cares about the static command shape).
        argv = [
            "msf-aux",
            "run",
            module,
            "RHOSTS=" + ",".join(targets),
        ]
        attck_ids, tactics = self._tags_for_module(module)
        return Command(
            adapter_name=self.name,
            argv=argv,
            target_scope=targets,
            attck_tactics=tactics,
            attck_technique_ids=attck_ids,
            is_active_probe=True,
            expected_runtime_seconds=180,
            rationale=(
                f"Phase I auxiliary scan: intent={task.intent!r} "
                f"module={module!r} scope={targets}"
            ),
        )

    def execute(self, command: Command, env: ExecutionEnv) -> Finding:
        self._enforce_phase1_policy(command, env)
        if self._client is None:
            raise MSFPolicyError("msfrpcd client not configured")

        module = self._module_from_argv(command.argv)
        rhosts = self._rhosts_from_argv(command.argv)

        result = self._client.module_run(module, {"RHOSTS": rhosts}) or {}
        parsed = self._normalize_result(result)
        cves = sorted({c for r in parsed.get("rows", []) for c in r.get("cves", [])})

        return Finding(
            adapter_name=self.name,
            task_id=parsed.get("task_id", ""),
            summary=self._summarize(module, parsed),
            raw_output_path=None,
            parsed=parsed,
            attck_technique_ids=command.attck_technique_ids,
            candidate_cves=cves,
        )

    # ---------- module selection ----------

    @staticmethod
    def _select_module(intent: str) -> str:
        i = intent.lower()
        if "smb" in i or "445" in i or "netbios" in i:
            return "auxiliary/scanner/smb/smb_version"
        if "rdp" in i or "3389" in i:
            return "auxiliary/scanner/rdp/rdp_scanner"
        if "ssh" in i:
            return "auxiliary/scanner/ssh/ssh_version"
        if "ftp" in i:
            return "auxiliary/scanner/ftp/ftp_version"
        if "snmp" in i:
            return "auxiliary/scanner/snmp/snmp_enum"
        if "http" in i or "web" in i:
            return "auxiliary/scanner/http/http_version"
        if "telnet" in i:
            return "auxiliary/scanner/telnet/telnet_version"
        if "mssql" in i or "ms-sql" in i:
            return "auxiliary/scanner/mssql/mssql_ping"
        if "mysql" in i:
            return "auxiliary/scanner/mysql/mysql_version"
        if "postgres" in i:
            return "auxiliary/scanner/postgres/postgres_version"
        return "auxiliary/scanner/portscan/tcp"

    @staticmethod
    def _tags_for_module(module: str) -> tuple[list[str], list[AttackTechnique]]:
        if "portscan" in module:
            return ["T1595.001", "T1018"], [
                AttackTechnique.RECONNAISSANCE,
                AttackTechnique.DISCOVERY,
            ]
        if "smb" in module or "netbios" in module:
            return ["T1135", "T1046"], [AttackTechnique.DISCOVERY]
        if "rdp" in module:
            return ["T1021.001", "T1046"], [AttackTechnique.DISCOVERY]
        if "ssh" in module:
            return ["T1021.004", "T1046"], [AttackTechnique.DISCOVERY]
        if "http" in module:
            return ["T1071.001", "T1046"], [AttackTechnique.DISCOVERY]
        return ["T1046"], [AttackTechnique.DISCOVERY]

    # ---------- validation ----------

    @classmethod
    def _validate_module(cls, module: str) -> None:
        if not module or not MODULE_RE.match(module):
            raise MSFPolicyError(f"invalid module syntax: {module!r}")
        if not module.startswith(PERMITTED_MODULE_PREFIX):
            raise MSFPolicyError(
                f"only {PERMITTED_MODULE_PREFIX}* modules are permitted in Phase I; "
                f"got {module!r}"
            )
        # Reject any name fragment that suggests state change or credentials.
        for frag in PROHIBITED_NAME_FRAGMENTS:
            if frag in module:
                raise MSFPolicyError(
                    f"module {module!r} contains prohibited fragment {frag!r}"
                )
        category = module.split("/", 3)[2] if module.count("/") >= 2 else ""
        if category not in ALLOWED_SCANNER_CATEGORIES:
            raise MSFPolicyError(
                f"scanner category {category!r} is not in the Phase I allow-list"
            )

    @staticmethod
    def _validate_targets(scope: list[str]) -> list[str]:
        if not scope:
            raise MSFTargetError("empty target scope")
        out: list[str] = []
        for raw in scope:
            t = raw.strip()
            if not t:
                continue
            try:
                ipaddress.ip_network(t, strict=False)
                out.append(t)
                continue
            except ValueError:
                pass
            # accept bare hostname or IP literal
            if re.match(r"^[A-Za-z0-9_.\-]+$", t):
                out.append(t)
            else:
                raise MSFTargetError(f"target syntax rejected: {t!r}")
        if not out:
            raise MSFTargetError("no valid targets after validation")
        return out

    @classmethod
    def _enforce_phase1_policy(cls, command: Command, env: ExecutionEnv) -> None:
        if env != ExecutionEnv.CALDERA_ONLY:
            raise MSFPolicyError(
                f"Phase I builds enforce CALDERA_ONLY execution; got {env}"
            )
        if command.is_impact_class():
            raise MSFPolicyError("Impact-tactic commands are not permitted in Phase I")
        module = cls._module_from_argv(command.argv)
        cls._validate_module(module)

    @staticmethod
    def _module_from_argv(argv: list[str]) -> str:
        # ["msf-aux", "run", "<module>", "RHOSTS=..."]
        if len(argv) < 3 or argv[1] != "run":
            raise MSFPolicyError(f"unexpected argv shape: {argv!r}")
        return argv[2]

    @staticmethod
    def _rhosts_from_argv(argv: list[str]) -> str:
        for a in argv[3:]:
            if a.startswith("RHOSTS="):
                return a[len("RHOSTS=") :]
        raise MSFPolicyError("RHOSTS not present in command argv")

    # ---------- result normalization ----------

    @staticmethod
    def _normalize_result(result: dict[str, Any]) -> dict[str, Any]:
        rows = result.get("rows") or result.get("results") or []
        normalized_rows: list[dict[str, Any]] = []
        for r in rows:
            host = r.get("host") or r.get("rhost") or ""
            info = r.get("info", "") or ""
            cves = sorted(set(CVE_RE.findall(str(info))))
            normalized_rows.append({
                "host": host,
                "info": info,
                "cves": cves,
                "port": r.get("port"),
                "service": r.get("service") or r.get("name") or "",
            })
        return {"rows": normalized_rows, "task_id": result.get("task_id", "")}

    @staticmethod
    def _summarize(module: str, parsed: dict[str, Any]) -> str:
        rows = parsed.get("rows", [])
        n_cves = sum(len(r.get("cves", [])) for r in rows)
        return f"{module}: {len(rows)} row(s), {n_cves} CVE candidate(s)"
