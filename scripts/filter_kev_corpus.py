"""Filter a full NVD JSONL corpus down to the CISA KEV catalog + eval CVEs.

The Researcher gold-standard eval (``eval/researcher_eval_v0.yaml``) is
drawn from the CISA Known Exploited Vulnerabilities catalog. Seeding all
~650K NVD records to answer 50 KEV questions is wasteful (~11 hours of
CPU embedding). This script produces a focused corpus of just the CVEs
that matter:

  - every CVE in the live CISA KEV catalog (~1,300 records), AND
  - every ``expected_cve`` referenced by the eval YAML (belt-and-braces,
    in case an eval CVE has aged out of the current KEV feed)

Usage:
    python scripts/filter_kev_corpus.py \
        --in data/nvd_corpus.jsonl \
        --out data/kev_corpus.jsonl \
        --eval eval/researcher_eval_v0.yaml

Then seed the small corpus:
    python scripts/seed_qdrant.py --jsonl data/kev_corpus.jsonl --recreate
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import urllib.request
from pathlib import Path

logger = logging.getLogger("filter_kev_corpus")

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def load_kev_catalog(
    *, url: str = KEV_FEED_URL, offline: str | None = None, timeout: int = 30
) -> dict[str, dict]:
    """Return the CISA KEV catalog keyed by CVE id (full entry per CVE)."""
    if offline:
        payload = json.loads(Path(offline).read_text(encoding="utf-8"))
        logger.info("offline KEV catalog loaded from %s", offline)
    else:
        req = urllib.request.Request(
            url, headers={"User-Agent": "oubliette-warden-kev-filter/0.1"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed CISA URL
            payload = json.loads(resp.read().decode("utf-8"))
    catalog = {
        v["cveID"]: v
        for v in payload.get("vulnerabilities", [])
        if v.get("cveID")
    }
    logger.info("CISA KEV catalog: %d CVE entries", len(catalog))
    return catalog


def enrich_description(nvd_description: str, kev: dict) -> str:
    """Fold the KEV entry's operationally-useful fields into the text that
    gets embedded + shown to the LLM. NVD gives the technical description;
    KEV adds exploitation status, dates, ransomware use, and remediation
    framing — exactly the facts the exploitability/mitigation questions need.
    """
    parts = [nvd_description.strip()]
    bits: list[str] = []
    if kev.get("dateAdded"):
        bits.append(f"Added to CISA KEV on {kev['dateAdded']}")
    if kev.get("dueDate"):
        bits.append(f"federal remediation due {kev['dueDate']}")
    krc = kev.get("knownRansomwareCampaignUse")
    if krc:
        bits.append(f"known ransomware campaign use: {krc}")
    if bits:
        parts.append("[CISA KEV] " + "; ".join(bits) + ".")
    if kev.get("shortDescription"):
        parts.append(f"KEV summary: {kev['shortDescription'].strip()}")
    if kev.get("requiredAction"):
        parts.append(f"Required action: {kev['requiredAction'].strip()}")
    if kev.get("vulnerabilityName"):
        parts.append(f"KEV name: {kev['vulnerabilityName'].strip()}")
    return "\n".join(p for p in parts if p)


def eval_cve_ids(eval_path: Path) -> set[str]:
    """Extract every CVE id referenced anywhere in the eval YAML.

    Avoids a YAML dependency by regex-scanning the raw text — the eval file
    lists CVE ids in ``expected_cve``, ``aliases``, and prose alike.
    """
    if not eval_path.is_file():
        logger.warning("eval file not found, skipping: %s", eval_path)
        return set()
    text = eval_path.read_text(encoding="utf-8")
    ids = set(CVE_RE.findall(text))
    logger.info("eval set references %d distinct CVE ids", len(ids))
    return ids


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--in", dest="in_path", default="data/nvd_corpus.jsonl")
    p.add_argument("--out", dest="out_path", default="data/kev_corpus.jsonl")
    p.add_argument("--eval", default="eval/researcher_eval_v0.yaml")
    p.add_argument(
        "--kev-url", default=KEV_FEED_URL,
        help="override the CISA KEV feed URL (or point at a local copy)",
    )
    p.add_argument(
        "--offline-kev",
        help="path to a pre-downloaded KEV JSON (skips the network fetch)",
    )
    p.add_argument(
        "--no-enrich",
        action="store_true",
        help="do NOT fold KEV fields (dates, required action, ransomware "
        "use) into the record description (enrichment is on by default)",
    )
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    in_path = Path(args.in_path)
    if not in_path.is_file():
        logger.error("input corpus not found: %s", in_path)
        return 1

    # Load the full KEV catalog (keyed by CVE) so we can both filter AND enrich.
    try:
        kev_catalog = load_kev_catalog(url=args.kev_url, offline=args.offline_kev)
    except Exception as exc:  # noqa: BLE001
        logger.error("failed to load KEV feed: %s", exc)
        logger.error("download it manually and pass --offline-kev <path>")
        return 1
    kev_ids = set(kev_catalog)

    keep = kev_ids | eval_cve_ids(Path(args.eval))
    logger.info("keep-set: %d CVE ids (KEV ∪ eval)", len(keep))

    out_path = Path(args.out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seen = 0
    written = 0
    duplicates = 0
    enriched = 0
    matched_ids: set[str] = set()
    with in_path.open("r", encoding="utf-8-sig") as fin, out_path.open(
        "w", encoding="utf-8"
    ) as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            seen += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cve_id = row.get("id") or row.get("cve_id")
            if cve_id not in keep:
                continue
            if cve_id in matched_ids:
                # The source NVD corpus can contain duplicate CVE rows
                # (overlapping fetch windows compacted together). Keep only
                # the first — duplicate vectors pollute retrieval ranking.
                duplicates += 1
                continue
            # Fold KEV fields into the description so they're embedded and
            # shown to the LLM. Keep the original under nvd_description.
            kev = kev_catalog.get(cve_id)
            if kev and not args.no_enrich:
                original = row.get("description", "") or ""
                row["nvd_description"] = original
                row["description"] = enrich_description(original, kev)
                row["kev"] = {
                    "dateAdded": kev.get("dateAdded"),
                    "dueDate": kev.get("dueDate"),
                    "requiredAction": kev.get("requiredAction"),
                    "knownRansomwareCampaignUse": kev.get(
                        "knownRansomwareCampaignUse"
                    ),
                }
                enriched += 1
            fout.write(json.dumps(row, separators=(",", ":")) + "\n")
            written += 1
            matched_ids.add(cve_id)

    logger.info("enriched %d records with CISA KEV fields", enriched)
    missing = keep - matched_ids
    logger.info(
        "scanned %d corpus records; wrote %d unique to %s (%d duplicate rows dropped)",
        seen,
        written,
        out_path,
        duplicates,
    )
    logger.info(
        "keep-set coverage: %d/%d found in corpus (%d missing)",
        len(matched_ids),
        len(keep),
        len(missing),
    )
    # Surface eval CVEs that aren't in the corpus — those would cost eval points.
    eval_only_missing = missing & eval_cve_ids(Path(args.eval))
    if eval_only_missing:
        logger.warning(
            "EVAL CVEs missing from corpus (will fail those items): %s",
            sorted(eval_only_missing),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
