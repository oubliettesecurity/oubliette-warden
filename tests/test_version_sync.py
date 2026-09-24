"""``oubliette_warden.__version__`` must match the version in pyproject.toml."""

from __future__ import annotations

from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")  # stdlib on 3.11+; skip on older Pythons

import oubliette_warden

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_dunder_version_matches_pyproject():
    with PYPROJECT.open("rb") as f:
        declared = tomllib.load(f)["project"]["version"]
    assert oubliette_warden.__version__ == declared


def test_operator_api_reports_package_version():
    pytest.importorskip("fastapi")
    from oubliette_warden.operator_ui.api import create_app
    from oubliette_warden.operator_ui.review_queue import ReviewQueue

    assert create_app(ReviewQueue()).version == oubliette_warden.__version__
