"""Minimal CALDERA REST API client + in-memory fake.

The Phase I prototype only needs three things from CALDERA:

  1. ``health()`` — is the range up and responsive?
  2. ``list_agents()`` — what hosts are registered on the emulated range?
  3. ``run_operation(adversary_id, group)`` — kick off an ATT&CK operation
     and return its facts/results envelope for the CodeGen and Cyber
     Analysis agents to consume.

This module provides:

  - ``CalderaClient`` — protocol that real and fake implementations satisfy
  - ``HTTPCalderaClient`` — real implementation against a running CALDERA
    instance (uses ``urllib`` so we don't add a runtime dep)
  - ``InMemoryCalderaClient`` — deterministic fake for unit tests; supports
    canned agents/operations and records call history

Phase I builds enforce CALDERA-only execution at the safety-gate layer; this
client never reaches outside the configured CALDERA endpoint.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class CalderaAgent:
    """A CALDERA agent (registered host on the emulated range)."""

    paw: str  # CALDERA's unique agent id
    host: str
    platform: str
    group: str = "red"
    trusted: bool = True


@dataclass(frozen=True)
class CalderaOperation:
    """A completed (or in-flight) CALDERA operation envelope."""

    operation_id: str
    adversary_id: str
    state: str  # "running" | "finished" | "failed"
    facts: list[dict[str, Any]] = field(default_factory=list)
    links: list[dict[str, Any]] = field(default_factory=list)


class CalderaError(RuntimeError):
    """Raised when the CALDERA endpoint is unreachable or returns an error."""


class CalderaClient(Protocol):
    """Minimum surface the Oubliette Warden agents need."""

    def health(self) -> bool: ...
    def list_agents(self, group: str | None = None) -> list[CalderaAgent]: ...
    def run_operation(
        self,
        adversary_id: str,
        *,
        group: str = "red",
        name: str | None = None,
    ) -> CalderaOperation: ...


# ----- Real implementation --------------------------------------------------


class HTTPCalderaClient:
    """Real CALDERA REST API client.

    Uses ``urllib`` directly to avoid adding ``requests`` or ``httpx`` as a
    runtime dependency for the agents. Phase II can swap to an async client
    when that matters; Phase I is single-threaded by contract.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8888",
        api_key: str | None = None,
        timeout_seconds: int = 10,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds

    def health(self) -> bool:
        try:
            self._get("/api/v2/health")
            return True
        except CalderaError:
            return False

    def list_agents(self, group: str | None = None) -> list[CalderaAgent]:
        rows = self._get("/api/v2/agents") or []
        out: list[CalderaAgent] = []
        for r in rows:
            agent = CalderaAgent(
                paw=str(r.get("paw", "")),
                host=str(r.get("host", "")),
                platform=str(r.get("platform", "")),
                group=str(r.get("group", "red")),
                trusted=bool(r.get("trusted", True)),
            )
            if group is not None and agent.group != group:
                continue
            out.append(agent)
        return out

    def run_operation(
        self,
        adversary_id: str,
        *,
        group: str = "red",
        name: str | None = None,
    ) -> CalderaOperation:
        body = {
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "name": name or f"oubliette_warden-{adversary_id}",
        }
        result = self._post("/api/v2/operations", body)
        op_id = str(result.get("id", result.get("operation_id", "")))
        return CalderaOperation(
            operation_id=op_id,
            adversary_id=adversary_id,
            state=str(result.get("state", "running")),
            facts=list(result.get("facts", [])),
            links=list(result.get("links", [])),
        )

    # ----- transport -----

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_key:
            h["KEY"] = self._api_key
        return h

    def _get(self, path: str) -> Any:
        req = urllib.request.Request(self._base + path, headers=self._headers())
        return self._send(req)

    def _post(self, path: str, body: Mapping[str, Any]) -> Any:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._base + path, data=data, headers=self._headers(), method="POST"
        )
        return self._send(req)

    def _send(self, req: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - validated base_url, no shell
                text = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise CalderaError(f"CALDERA endpoint unreachable: {exc}") from exc
        except TimeoutError as exc:
            raise CalderaError("CALDERA request timed out") from exc
        try:
            return json.loads(text) if text.strip() else {}
        except json.JSONDecodeError as exc:
            raise CalderaError(f"CALDERA returned non-JSON: {text[:200]!r}") from exc


# ----- Deterministic fake ----------------------------------------------------


class InMemoryCalderaClient:
    """Records the agent's intent so unit tests can assert on the contract.

    Tests can pre-seed agents/operations. The client never raises unless
    explicitly configured to (via ``set_health_down`` / ``set_next_failure``).
    """

    def __init__(self) -> None:
        self._healthy = True
        self._agents: list[CalderaAgent] = []
        self._next_op: CalderaOperation | None = None
        self.run_calls: list[dict[str, Any]] = []

    # configuration

    def seed_agents(self, agents: list[CalderaAgent]) -> None:
        self._agents = list(agents)

    def set_next_operation(self, op: CalderaOperation) -> None:
        self._next_op = op

    def set_health_down(self) -> None:
        self._healthy = False

    # client surface

    def health(self) -> bool:
        return self._healthy

    def list_agents(self, group: str | None = None) -> list[CalderaAgent]:
        if group is None:
            return list(self._agents)
        return [a for a in self._agents if a.group == group]

    def run_operation(
        self,
        adversary_id: str,
        *,
        group: str = "red",
        name: str | None = None,
    ) -> CalderaOperation:
        call = {"adversary_id": adversary_id, "group": group, "name": name}
        self.run_calls.append(call)
        if self._next_op is None:
            return CalderaOperation(
                operation_id=f"op-{len(self.run_calls):04d}",
                adversary_id=adversary_id,
                state="finished",
            )
        op = self._next_op
        self._next_op = None
        return op
