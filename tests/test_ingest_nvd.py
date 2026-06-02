"""Smoke tests for ingest_nvd.py — no network calls."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import ingest_nvd as iv  # noqa: E402


def test_flatten_minimal():
    cve = {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T00:00:00.000",
        "lastModified": "2024-01-01T00:00:00.000",
        "vulnStatus": "Modified",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 JNDI features..."},
            {"lang": "es", "value": "..."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
    }
    out = iv._flatten_cve(cve)
    assert out is not None
    assert out["id"] == "CVE-2021-44228"
    assert out["description"].startswith("Apache Log4j2")
    assert out["cvss"]["baseScore"] == 10.0
    assert out["cvss"]["baseSeverity"] == "CRITICAL"
    assert "CWE-502" in out["cwes"]
    assert any("log4j" in c for c in out["cpes"])
    assert any("apache.org" in r for r in out["references"])


def test_flatten_no_id_returns_none():
    assert iv._flatten_cve({"descriptions": []}) is None


def test_flatten_picks_v31_over_v2():
    cve = {
        "id": "CVE-X",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {
            "cvssMetricV2": [
                {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N"}}
            ],
            "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.0, "baseSeverity": "HIGH"}}
            ],
        },
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }
    out = iv._flatten_cve(cve)
    assert out["cvss"]["version"] == "3.1"
    assert out["cvss"]["baseScore"] == 9.0


def test_flatten_no_metrics():
    cve = {
        "id": "CVE-Y",
        "descriptions": [{"lang": "en", "value": "y"}],
        "metrics": {},
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }
    out = iv._flatten_cve(cve)
    assert out["cvss"] is None


def test_iter_windows_chunks_120_days():
    from datetime import datetime, timezone

    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 12, 31, tzinfo=timezone.utc)
    windows = list(iv._iter_windows(start, end))
    assert len(windows) >= 3
    for w_start, w_end in windows:
        delta = (w_end - w_start).days
        assert delta <= 120
    assert windows[0][0] == start
    assert windows[-1][1] == end


def test_rate_limit_with_and_without_key():
    rl_no_key = iv.RateLimit.for_key(False)
    rl_key = iv.RateLimit.for_key(True)
    assert rl_no_key.requests_per_window == 5
    assert rl_key.requests_per_window == 50
    assert rl_no_key.window_seconds == 30
