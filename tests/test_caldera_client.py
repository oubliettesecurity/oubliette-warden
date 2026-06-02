"""Tests for the CALDERA client + in-memory fake."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.integration.caldera_client import (  # noqa: E402
    CalderaAgent,
    CalderaError,
    CalderaOperation,
    HTTPCalderaClient,
    InMemoryCalderaClient,
)


# ----- InMemoryCalderaClient ----------------------------------------------


@pytest.fixture
def fake():
    return InMemoryCalderaClient()


def test_default_health_is_up(fake):
    assert fake.health() is True


def test_health_down_after_explicit_flip(fake):
    fake.set_health_down()
    assert fake.health() is False


def test_list_agents_empty_by_default(fake):
    assert fake.list_agents() == []


def test_seed_and_filter_agents_by_group(fake):
    fake.seed_agents([
        CalderaAgent(paw="a1", host="dvwa", platform="linux", group="blue"),
        CalderaAgent(paw="a2", host="kdc", platform="windows", group="red"),
    ])
    assert len(fake.list_agents()) == 2
    assert len(fake.list_agents(group="red")) == 1
    assert fake.list_agents(group="red")[0].host == "kdc"


def test_run_operation_default_returns_finished_op(fake):
    op = fake.run_operation(adversary_id="adv-recon")
    assert op.state == "finished"
    assert op.adversary_id == "adv-recon"
    assert op.operation_id.startswith("op-")


def test_run_operation_records_call_history(fake):
    fake.run_operation(adversary_id="adv-recon")
    fake.run_operation(adversary_id="adv-disco", group="red", name="phase1-disco")
    assert len(fake.run_calls) == 2
    assert fake.run_calls[1]["adversary_id"] == "adv-disco"
    assert fake.run_calls[1]["name"] == "phase1-disco"


def test_set_next_operation_overrides_default(fake):
    canned = CalderaOperation(
        operation_id="op-canned",
        adversary_id="adv-x",
        state="finished",
        facts=[{"trait": "host.ip", "value": "10.50.0.10"}],
    )
    fake.set_next_operation(canned)
    out = fake.run_operation(adversary_id="adv-x")
    assert out.operation_id == "op-canned"
    assert out.facts[0]["value"] == "10.50.0.10"
    # Canned op is consumed; next call returns a fresh default.
    out2 = fake.run_operation(adversary_id="adv-x")
    assert out2.operation_id != "op-canned"


# ----- HTTPCalderaClient (transport-only checks) ---------------------------


def test_http_client_builds_headers_with_api_key():
    c = HTTPCalderaClient(base_url="http://example.invalid", api_key="secret")
    headers = c._headers()  # noqa: SLF001 - intentional white-box
    assert headers["KEY"] == "secret"
    assert headers["Accept"] == "application/json"


def test_http_client_omits_api_key_when_none():
    c = HTTPCalderaClient(base_url="http://example.invalid", api_key=None)
    headers = c._headers()  # noqa: SLF001
    assert "KEY" not in headers


def test_http_client_health_returns_false_on_unreachable():
    c = HTTPCalderaClient(
        base_url="http://nonexistent-host-12345.invalid",
        timeout_seconds=1,
    )
    # health() catches CalderaError and returns False so callers can
    # branch without try/except.
    assert c.health() is False


def test_http_client_run_operation_raises_on_unreachable():
    c = HTTPCalderaClient(
        base_url="http://nonexistent-host-12345.invalid",
        timeout_seconds=1,
    )
    with pytest.raises(CalderaError):
        c.run_operation(adversary_id="adv-recon")
