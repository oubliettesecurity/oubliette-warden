"""Syntax-level validation of the CALDERA Docker compose file.

We can't reasonably spin CALDERA in CI for a unit test, but the compose
file itself is a deliverable: it must parse, declare the required
services, pin its images, and bind risky ports to localhost only.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

COMPOSE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "caldera-compose.yml"

REQUIRED_SERVICES = {"caldera", "qdrant"}


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_compose_file_parses(compose):
    assert isinstance(compose, dict)
    assert "services" in compose


def test_required_services_are_present(compose):
    services = compose["services"]
    missing = REQUIRED_SERVICES - set(services)
    assert not missing, f"missing required services: {missing}"


def test_no_service_uses_latest_tag(compose):
    """`:latest` is forbidden — eval-run reproducibility depends on pinning."""
    offenders: list[str] = []
    for name, svc in compose["services"].items():
        img = svc.get("image", "")
        if img.endswith(":latest"):
            offenders.append(f"{name}={img}")
    assert not offenders, f"services using :latest tag: {offenders}"


def test_all_published_ports_bind_localhost(compose):
    """Phase I never exposes substrate services beyond the dev workstation."""
    leaks: list[str] = []
    for name, svc in compose["services"].items():
        for port in svc.get("ports", []):
            if not str(port).startswith("127.0.0.1:"):
                leaks.append(f"{name}: {port}")
    assert not leaks, f"ports not bound to localhost: {leaks}"


def test_caldera_healthcheck_present(compose):
    caldera = compose["services"]["caldera"]
    assert "healthcheck" in caldera, "CALDERA service must declare a healthcheck"


def test_persistent_volumes_declared(compose):
    """State must survive container restarts between eval iterations."""
    volumes = compose.get("volumes", {})
    for required in ("caldera-data", "caldera-conf", "qdrant-data"):
        assert required in volumes, f"missing named volume: {required}"
