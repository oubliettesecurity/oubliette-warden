"""The published artifacts must contain only the ``oubliette_warden`` package.

``oubliette-warden`` is a public PyPI package. The repo also holds things that
have no place in it: ``tests/``, ``experiments/``, ``eval/``, ``scripts/``,
``docs/``, CI config and any local ``.env`` or key material.

This is an allowlist check: anything outside the expected layout fails.
This module deliberately imports nothing from ``oubliette_warden`` so the publish
workflow can run it with ``--noconftest`` in a venv that has only build
tooling installed.

The artifact tests skip when ``dist/`` is empty so they never block a plain
test run. Set ``WARDEN_REQUIRE_DIST=1`` (the publish workflow and the CI build job do) to
make a missing build a hard failure instead of a silent skip.
"""

from __future__ import annotations

import os
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "oubliette_warden"
# Normalized distribution name, as used in the dist-info / egg-info dirs.
DIST = "oubliette_warden"

# Path fragments that must never appear anywhere in a built artifact.
FORBIDDEN_FRAGMENTS = (
    "/tests/",
    "/experiments/",
    "/eval/",
    "/scripts/",
    "/docs/",
    "/data/",
    "/.git/",
    "/.github/",
    "/node_modules/",
)
FORBIDDEN_BASENAMES = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.pem|.*\.key|id_rsa.*|.*\.sqlite3?|.*\.db)$"
)
SDIST_ALLOWED_TOP = {
    "LICENSE",
    "NOTICE",
    "README.md",
    "pyproject.toml",
    "setup.cfg",
    "PKG-INFO",
    "MANIFEST.in",
}


def _dist_artifacts() -> tuple[list[Path], list[Path]]:
    dist = REPO_ROOT / "dist"
    return sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))


def _require_or_skip(artifacts: list[Path], kind: str) -> None:
    if artifacts:
        return
    if os.getenv("WARDEN_REQUIRE_DIST") == "1":
        pytest.fail(f"WARDEN_REQUIRE_DIST=1 but no {kind} found in dist/")
    pytest.skip(f"no {kind} in dist/ -- nothing to inspect")


def _generic_offenders(names: list[str]) -> list[str]:
    bad = []
    for n in names:
        probe = "/" + n
        if any(
            frag in probe for frag in FORBIDDEN_FRAGMENTS
        ) or FORBIDDEN_BASENAMES.search(n):
            bad.append(n)
    return bad


def test_setuptools_config_only_finds_the_package() -> None:
    setuptools = pytest.importorskip(
        "setuptools", reason="setuptools required to resolve packages"
    )
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        find_cfg = tomllib.load(fh)["tool"]["setuptools"]["packages"]["find"]
    where = REPO_ROOT / find_cfg.get("where", ["."])[0]
    shipped = setuptools.find_packages(
        where=str(where),
        include=find_cfg.get("include", ["*"]),
        exclude=find_cfg.get("exclude", []),
    )
    # Discrimination: the resolver must actually return the package, otherwise
    # the allowlist assertion below would pass vacuously.
    assert PACKAGE in shipped, f"package resolution looks broken: {shipped!r}"
    stray = [p for p in shipped if p != PACKAGE and not p.startswith(PACKAGE + ".")]
    assert not stray, f"non-{PACKAGE} packages would ship: {sorted(stray)}"


def test_wheel_contains_only_the_package() -> None:
    wheels, _ = _dist_artifacts()
    _require_or_skip(wheels, "wheel")
    offenders: dict[str, list[str]] = {}
    dist_info = re.compile(rf"^{DIST}-[^/]+\.dist-info/")
    for whl in wheels:
        with zipfile.ZipFile(whl) as zf:
            names = zf.namelist()
        outside = [
            n for n in names if not (n.startswith(PACKAGE + "/") or dist_info.match(n))
        ]
        bad = sorted(set(outside + _generic_offenders(names)))
        assert any(n.startswith(PACKAGE + "/") for n in names), (
            f"{whl.name} has no package files"
        )
        if bad:
            offenders[whl.name] = bad
    assert not offenders, f"wheel contains files outside {PACKAGE}/: {offenders}"


def test_sdist_contains_only_expected_files() -> None:
    _, sdists = _dist_artifacts()
    _require_or_skip(sdists, "sdist")
    offenders: dict[str, list[str]] = {}
    for sd in sdists:
        with tarfile.open(sd) as tf:
            members = [m.name for m in tf.getmembers() if m.isfile()]
        bad = []
        for name in members:
            _, _, rel = name.partition("/")  # strip "<name>-<version>/"
            ok = rel in SDIST_ALLOWED_TOP or rel.startswith(
                (f"src/{PACKAGE}/", f"src/{DIST}.egg-info/")
            )
            if not ok:
                bad.append(name)
        bad = sorted(set(bad + _generic_offenders(members)))
        if bad:
            offenders[sd.name] = bad
    assert not offenders, f"sdist contains unexpected files: {offenders}"
