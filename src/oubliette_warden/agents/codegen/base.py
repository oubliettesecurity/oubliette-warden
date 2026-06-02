"""
Command-adapter base for the Oubliette Warden Code Generation & Execution agent.

Tools that the CodeGen agent can emit (Nmap, MSF auxiliary modules, etc.) implement
this protocol. Adapters are responsible for:

  1. Generating a parameterized command from a structured Task record
  2. Declaring the command's safety attributes so the safety pipeline can gate it
  3. Executing the command in the configured emulation substrate (CALDERA-only
     in Phase I — enforced by policy, not by adapter politeness)
  4. Parsing the tool's output into a normalized Finding record

The adapter does NOT decide whether to run a command. That is the safety
pipeline's job. Adapters surface metadata; gates make decisions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionEnv(str, Enum):
    """Where a command is allowed to execute. Phase I is CALDERA_ONLY."""

    CALDERA_ONLY = "caldera_only"
    LAB_RANGE = "lab_range"  # Phase II only
    LIVE = "live"  # Phase III only, never reachable in Phase I builds


class AttackTechnique(str, Enum):
    """Coarse ATT&CK tactic bucket — adapters declare what they enable."""

    RECONNAISSANCE = "TA0043"
    DISCOVERY = "TA0007"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass(frozen=True)
class Task:
    """A single planning-graph node handed to the CodeGen agent."""

    task_id: str
    intent: str
    target_scope: list[str]
    attck_technique_ids: list[str] = field(default_factory=list)
    operator_approved: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Command:
    """A concrete shell-class command emitted by an adapter, pre-gate."""

    adapter_name: str
    argv: list[str]
    target_scope: list[str]
    attck_tactics: list[AttackTechnique]
    attck_technique_ids: list[str]
    is_active_probe: bool
    expected_runtime_seconds: int
    rationale: str

    def is_impact_class(self) -> bool:
        return AttackTechnique.IMPACT in self.attck_tactics


@dataclass(frozen=True)
class Finding:
    """Normalized output from an adapter, post-execution."""

    adapter_name: str
    task_id: str
    summary: str
    raw_output_path: str | None
    parsed: dict[str, Any]
    attck_technique_ids: list[str] = field(default_factory=list)
    candidate_cves: list[str] = field(default_factory=list)


class CommandAdapter(ABC):
    """Base class for any tool the CodeGen agent can emit and execute."""

    name: str = ""
    version: str = "0.0.0"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying tool binary is present and runnable."""

    @abstractmethod
    def plan(self, task: Task) -> Command:
        """Translate a task into a concrete Command (no execution yet)."""

    @abstractmethod
    def execute(self, command: Command, env: ExecutionEnv) -> Finding:
        """Execute a Command in the given environment and return a Finding."""

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "available": self.is_available(),
        }
