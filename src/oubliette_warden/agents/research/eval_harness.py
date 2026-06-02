"""
Eval harness — runs the YAML gold-standard eval set against the Researcher.

CLI:
    python -m oubliette_warden.agents.research.eval_harness --eval eval/researcher_eval_v0.yaml

Prints a per-category breakdown plus a final score. Exit code 0 if the score
meets the configured threshold (default 0.80 — Phase I §2 Objective 5
acceptance criterion); 1 otherwise so CI can gate on it.

The harness scores three things per item:
  - cve_match     — answer mentions the expected CVE id(s)
  - cited         — answer carries at least one well-formed citation
  - keywords      — expected keywords (for mitigate/chain items) appear

A "pass" requires cve_match AND cited (when expected_cve is present).
For attck-only items, attck-token presence substitutes for cve_match.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .researcher import CVE_RE, Researcher
from .stub_backends import seed_researcher

ATTCK_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass
class ItemResult:
    item_id: str
    category: str
    passed: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    items: list[ItemResult] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.items)

    @property
    def n_passed(self) -> int:
        return sum(1 for i in self.items if i.passed)

    @property
    def score(self) -> float:
        return 0.0 if not self.items else self.n_passed / self.n

    def by_category(self) -> dict[str, tuple[int, int]]:
        bucket: dict[str, list[ItemResult]] = {}
        for item in self.items:
            bucket.setdefault(item.category, []).append(item)
        return {
            cat: (sum(1 for r in rs if r.passed), len(rs))
            for cat, rs in sorted(bucket.items())
        }


def load_eval_set(path: Path) -> list[dict[str, Any]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "items" not in payload:
        raise ValueError(f"eval set {path} does not have an 'items' list")
    return payload["items"]


def grade_item(researcher: Researcher, item: dict[str, Any], judge=None) -> ItemResult:
    item_id = item.get("id", "?")
    category = item.get("category", "?")
    prompt = item.get("prompt", "")
    if "context" in item:
        prompt = f"Context: {item['context'].strip()}\n\nQuestion: {prompt}"

    answer = researcher.answer(prompt)

    # v1 grading: semantic LLM judge (AISI-recommended) when supplied.
    if judge is not None:
        verdict = judge.grade(item, answer.text)
        return ItemResult(
            item_id=item_id,
            category=category,
            passed=verdict.passed,
            reasons=[] if verdict.passed else [verdict.reason],
        )

    reasons: list[str] = []

    expected_cve = item.get("expected_cve")
    expected_cves = item.get("expected_cves") or ([expected_cve] if expected_cve else [])
    expected_attck = (
        item.get("expected_attck")
        or item.get("must_reference_attck")
        or []
    )
    chained_with = item.get("chained_with")
    if chained_with:
        expected_cves = list(expected_cves) + [chained_with]

    cves_in_answer = set(answer.cves_mentioned)

    cve_ok = True
    if expected_cves:
        cves_match = set(expected_cves) & cves_in_answer
        if item.get("must_match_all"):
            cve_ok = set(expected_cves).issubset(cves_in_answer)
            if not cve_ok:
                reasons.append(f"missing cves: {set(expected_cves) - cves_in_answer}")
        else:
            cve_ok = bool(cves_match)
            if not cve_ok:
                reasons.append(f"no expected cve found; expected one of {expected_cves}")

    attck_ok = True
    if expected_attck and not expected_cves:
        # attck-only items
        attck_in_answer = set(ATTCK_RE.findall(answer.text))
        if item.get("must_match_all"):
            attck_ok = set(expected_attck).issubset(attck_in_answer)
        else:
            attck_ok = bool(set(expected_attck) & attck_in_answer)
        if not attck_ok:
            reasons.append(f"no expected attck token found; expected one of {expected_attck}")

    cited_ok = True
    if item.get("must_cite", False) or expected_cves:
        cited_ok = not answer.is_uncited()
        if not cited_ok:
            reasons.append("answer carries no citation")

    keywords = item.get("expected_keywords") or item.get("rationale_keywords") or []
    kw_ok = True
    if keywords:
        text_low = answer.text.lower()
        kw_ok = any(k.lower() in text_low for k in keywords)
        if not kw_ok:
            reasons.append(f"none of expected keywords present: {keywords}")

    passed = cve_ok and attck_ok and cited_ok and kw_ok
    return ItemResult(item_id=item_id, category=category, passed=passed, reasons=reasons)


def _build_backends(
    backend: str,
    *,
    ollama_url: str,
    qdrant_url: str,
    collection: str,
    gen_model: str,
    embed_model: str,
):
    """Return (retriever, llm) for the named backend."""
    if backend == "stub":
        return seed_researcher()
    if backend == "ollama":
        # Late-import so the stub path doesn't require these modules at all.
        from .ollama_backend import (
            OllamaEmbedder,
            OllamaLanguageModel,
            OllamaTransport,
        )
        from .qdrant_backend import QdrantRetriever, QdrantTransport

        ollama = OllamaTransport(base_url=ollama_url)
        embedder = OllamaEmbedder(model=embed_model, transport=ollama)
        llm = OllamaLanguageModel(model=gen_model, transport=ollama)
        retriever = QdrantRetriever(
            embedder=embedder,
            collection=collection,
            transport=QdrantTransport(base_url=qdrant_url),
        )
        return retriever, llm
    raise ValueError(f"unknown backend: {backend!r}")


def run(
    eval_path: Path,
    *,
    threshold: float = 0.80,
    backend: str = "stub",
    ollama_url: str = "http://127.0.0.1:11434",
    qdrant_url: str = "http://127.0.0.1:6333",
    collection: str = "nvd_corpus",
    gen_model: str = "llama3.1:8b",
    embed_model: str = "nomic-embed-text",
    k: int = 5,
    grader: str = "keyword",
    judge_model: str | None = None,
) -> EvalReport:
    retriever, llm = _build_backends(
        backend,
        ollama_url=ollama_url,
        qdrant_url=qdrant_url,
        collection=collection,
        gen_model=gen_model,
        embed_model=embed_model,
    )
    researcher = Researcher(retriever=retriever, llm=llm, k=k)

    judge = None
    if grader == "llm":
        if backend != "ollama":
            raise ValueError("--grader llm requires --backend ollama")
        from .eval_judge import LLMJudge, OllamaJudgeAdapter
        from .ollama_backend import OllamaTransport

        judge = LLMJudge(
            OllamaJudgeAdapter(
                model=judge_model or gen_model,
                transport=OllamaTransport(base_url=ollama_url),
            )
        )

    report = EvalReport()
    for item in load_eval_set(eval_path):
        report.items.append(grade_item(researcher, item, judge=judge))
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Oubliette Warden Researcher eval harness")
    p.add_argument(
        "--eval",
        default="eval/researcher_eval_v0.yaml",
        help="Path to YAML eval set",
    )
    p.add_argument("--threshold", type=float, default=0.80)
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.add_argument(
        "--backend",
        choices=("stub", "ollama"),
        default="stub",
        help="stub = deterministic backends (default); ollama = real Ollama+Qdrant",
    )
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    p.add_argument("--qdrant-url", default="http://127.0.0.1:6333")
    p.add_argument("--collection", default="nvd_corpus")
    p.add_argument("--gen-model", default="llama3.1:8b")
    p.add_argument("--embed-model", default="nomic-embed-text")
    p.add_argument(
        "--k", type=int, default=5,
        help="retrieval depth — records pulled into the LLM context per question",
    )
    p.add_argument(
        "--grader",
        choices=("keyword", "llm"),
        default="keyword",
        help="keyword = brittle substring match (v0); llm = semantic LLM "
        "judge (v1, AISI-recommended). llm requires --backend ollama.",
    )
    p.add_argument(
        "--judge-model",
        default=None,
        help="model for the LLM judge (default: same as --gen-model; a "
        "stronger model reduces grading bias)",
    )
    args = p.parse_args(argv)

    report = run(
        Path(args.eval),
        threshold=args.threshold,
        backend=args.backend,
        ollama_url=args.ollama_url,
        qdrant_url=args.qdrant_url,
        collection=args.collection,
        gen_model=args.gen_model,
        embed_model=args.embed_model,
        k=args.k,
        grader=args.grader,
        judge_model=args.judge_model,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "n": report.n,
                    "passed": report.n_passed,
                    "score": round(report.score, 4),
                    "by_category": {
                        c: {"passed": p, "total": t}
                        for c, (p, t) in report.by_category().items()
                    },
                    "failed": [
                        {"id": i.item_id, "reasons": i.reasons}
                        for i in report.items
                        if not i.passed
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"Oubliette Warden Researcher eval — {report.n_passed}/{report.n} ({report.score:.2%})")
        for cat, (passed, total) in report.by_category().items():
            print(f"  {cat:8s}  {passed}/{total}")
        failed = [i for i in report.items if not i.passed]
        if failed:
            print()
            print("Failed items:")
            for i in failed[:10]:
                print(f"  {i.item_id} [{i.category}] — {'; '.join(i.reasons)}")
            if len(failed) > 10:
                print(f"  ... and {len(failed) - 10} more")

    return 0 if report.score >= args.threshold else 1


if __name__ == "__main__":
    sys.exit(main())
