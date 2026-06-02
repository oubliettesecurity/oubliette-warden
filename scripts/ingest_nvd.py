"""
NVD CVE 2.0 ingestion harness for the Oubliette Warden Researcher agent.

Pulls public NIST NVD records page-by-page from the CVE 2.0 REST API,
caches raw JSON to disk, and emits a flat JSONL file ready for vector
indexing. Defaults to *no chunking* — chunking is the indexer's job, not
the ingestor's.

Public-domain data only. No credentials required. Respects NVD's
published rate limits (5 requests / 30 sec without API key,
50 requests / 30 sec with key).

Usage:
    python ingest_nvd.py fetch --since 2002-01-01 --until 2026-05-08
    python ingest_nvd.py compact --out data/nvd_corpus.jsonl
    python ingest_nvd.py stats
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib import error, request

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
DEFAULT_CACHE = Path("data") / "nvd_cache"
DEFAULT_OUT = Path("data") / "nvd_corpus.jsonl"
USER_AGENT = "oubliette-warden/0.1 (researcher-rag-ingest)"

logger = logging.getLogger("ingest_nvd")


@dataclass(frozen=True)
class RateLimit:
    requests_per_window: int
    window_seconds: int

    @classmethod
    def for_key(cls, has_api_key: bool) -> "RateLimit":
        return cls(50, 30) if has_api_key else cls(5, 30)


def _http_get(url: str, api_key: str | None) -> dict[str, Any]:
    req = request.Request(url, headers={"User-Agent": USER_AGENT})
    if api_key:
        req.add_header("apiKey", api_key)
    with request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _format_iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def _iter_windows(start: datetime, end: datetime, step_days: int = 120) -> Iterator[tuple[datetime, datetime]]:
    """NVD limits date windows to <= 120 days; chunk accordingly."""
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=step_days), end)
        yield cursor, window_end
        cursor = window_end


def fetch(
    since: datetime,
    until: datetime,
    cache_dir: Path,
    api_key: str | None,
    sleep_floor: float = 0.6,
) -> int:
    cache_dir.mkdir(parents=True, exist_ok=True)
    rl = RateLimit.for_key(api_key is not None)
    sleep_each = max(sleep_floor, rl.window_seconds / rl.requests_per_window)
    total = 0

    for w_start, w_end in _iter_windows(since, until):
        start_idx = 0
        window_label = f"{w_start.date()}_{w_end.date()}"
        while True:
            params = (
                f"?lastModStartDate={_format_iso(w_start)}"
                f"&lastModEndDate={_format_iso(w_end)}"
                f"&resultsPerPage={PAGE_SIZE}"
                f"&startIndex={start_idx}"
            )
            url = NVD_BASE + params
            attempt = 0
            while True:
                try:
                    data = _http_get(url, api_key)
                    break
                except error.HTTPError as exc:
                    attempt += 1
                    if exc.code in (429, 503) and attempt <= 5:
                        backoff = sleep_each * (2 ** attempt)
                        logger.warning("NVD %s — backoff %.1fs (attempt %d)", exc.code, backoff, attempt)
                        time.sleep(backoff)
                        continue
                    raise

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            page_path = cache_dir / f"nvd_{window_label}_{start_idx:06d}.json"
            page_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            total += len(vulns)
            logger.info("window=%s startIndex=%d wrote=%d total=%d", window_label, start_idx, len(vulns), total)

            total_results = int(data.get("totalResults", 0))
            start_idx += PAGE_SIZE
            if start_idx >= total_results:
                break
            time.sleep(sleep_each)

    return total


def compact(cache_dir: Path, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as out_f:
        for page in sorted(cache_dir.glob("nvd_*.json")):
            payload = json.loads(page.read_text(encoding="utf-8"))
            for entry in payload.get("vulnerabilities", []):
                cve = entry.get("cve", {})
                record = _flatten_cve(cve)
                if record is None:
                    continue
                out_f.write(json.dumps(record, separators=(",", ":")) + "\n")
                written += 1
    logger.info("compacted %d records → %s", written, out_path)
    return written


def _flatten_cve(cve: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descriptions = cve.get("descriptions", [])
    en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = _pick_cvss(metrics)
    weaknesses = [
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    ]
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    cpes = [
        m.get("criteria")
        for cfg in cve.get("configurations", [])
        for n in cfg.get("nodes", [])
        for m in n.get("cpeMatch", [])
        if m.get("criteria") and m.get("vulnerable")
    ]
    return {
        "id": cve_id,
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": en,
        "cvss": cvss,
        "cwes": list(dict.fromkeys(weaknesses)),
        "cpes": list(dict.fromkeys(cpes)),
        "references": refs,
    }


def _pick_cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((m for m in items if m.get("type") == "Primary"), items[0])
        cd = primary.get("cvssData", {})
        return {
            "version": cd.get("version"),
            "baseScore": cd.get("baseScore"),
            "baseSeverity": cd.get("baseSeverity"),
            "vector": cd.get("vectorString"),
        }
    return None


def stats(cache_dir: Path, corpus_path: Path) -> None:
    pages = list(cache_dir.glob("nvd_*.json"))
    print(f"cache_dir       : {cache_dir}")
    print(f"page count      : {len(pages)}")
    if corpus_path.exists():
        with corpus_path.open(encoding="utf-8") as f:
            n = sum(1 for _ in f)
        print(f"corpus records  : {n}  ({corpus_path})")
    else:
        print(f"corpus records  : (no compacted file at {corpus_path})")


def _parse_date(raw: str) -> datetime:
    return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="NVD ingestion harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("fetch", help="Pull NVD records to local JSON cache")
    pf.add_argument("--since", default="2002-01-01", help="Inclusive start (YYYY-MM-DD)")
    pf.add_argument("--until", default=datetime.now(timezone.utc).date().isoformat(), help="Exclusive end (YYYY-MM-DD)")
    pf.add_argument("--cache", default=str(DEFAULT_CACHE))
    pf.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))

    pc = sub.add_parser("compact", help="Flatten cache into single JSONL corpus")
    pc.add_argument("--cache", default=str(DEFAULT_CACHE))
    pc.add_argument("--out", default=str(DEFAULT_OUT))

    ps = sub.add_parser("stats", help="Show cache + corpus counts")
    ps.add_argument("--cache", default=str(DEFAULT_CACHE))
    ps.add_argument("--corpus", default=str(DEFAULT_OUT))

    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if args.cmd == "fetch":
        n = fetch(
            since=_parse_date(args.since),
            until=_parse_date(args.until),
            cache_dir=Path(args.cache),
            api_key=args.api_key,
        )
        print(f"fetched {n} records")
    elif args.cmd == "compact":
        n = compact(Path(args.cache), Path(args.out))
        print(f"compacted {n} records")
    elif args.cmd == "stats":
        stats(Path(args.cache), Path(args.corpus))
    return 0


if __name__ == "__main__":
    sys.exit(main())
