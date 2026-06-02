"""Run a single eval item against the real backend and print everything.

Diagnostic for "why did this item fail?" questions. Prints the question,
the retrieved CVE ids + scores, the raw model output, the citations
attached, the integrity-guard report, and (optionally) the judge's verdict
+ reason.

Usage:
    python scripts/probe_eval_item.py r-id-001 --gen-model qwen2.5:14b --judge
    python scripts/probe_eval_item.py r-mitigate-001 --k 8
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml  # noqa: E402

from oubliette_warden.agents.research.eval_harness import _build_backends  # noqa: E402
from oubliette_warden.agents.research.researcher import Researcher  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("item_id", help="id of the eval item, e.g. r-id-001")
    p.add_argument("--eval", default="eval/researcher_eval_v0.yaml")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    p.add_argument("--qdrant-url", default="http://127.0.0.1:6333")
    p.add_argument("--collection", default="nvd_corpus")
    p.add_argument("--gen-model", default="llama3.1:8b")
    p.add_argument("--embed-model", default="mxbai-embed-large")
    p.add_argument("--k", type=int, default=8)
    p.add_argument("--judge", action="store_true", help="also run the LLM judge")
    p.add_argument("--judge-model", default=None)
    args = p.parse_args(argv)

    items = yaml.safe_load(Path(args.eval).read_text(encoding="utf-8"))["items"]
    item = next((i for i in items if i.get("id") == args.item_id), None)
    if item is None:
        print(f"item {args.item_id!r} not found in {args.eval}", file=sys.stderr)
        return 1

    retriever, llm = _build_backends(
        "ollama",
        ollama_url=args.ollama_url,
        qdrant_url=args.qdrant_url,
        collection=args.collection,
        gen_model=args.gen_model,
        embed_model=args.embed_model,
    )
    researcher = Researcher(retriever=retriever, llm=llm, k=args.k)

    prompt = item["prompt"].strip()
    if "context" in item:
        prompt = f"Context: {item['context'].strip()}\n\nQuestion: {prompt}"

    print(f"=== item: {item['id']} ({item.get('category', '?')}) ===")
    print(f"QUESTION:\n{prompt}\n")

    expected = item.get("expected_cves") or (
        [item["expected_cve"]] if item.get("expected_cve") else []
    )
    print(f"RUBRIC expected_cves: {expected}")
    if item.get("expected_keywords") or item.get("rationale_keywords"):
        kw = item.get("expected_keywords") or item.get("rationale_keywords")
        print(f"RUBRIC expected_keywords: {kw}")
    if item.get("expected_attck"):
        print(f"RUBRIC expected_attck (supplementary): {item['expected_attck']}")
    print()

    # Retrieval visibility
    retrieved = list(retriever.retrieve(prompt, k=args.k))
    print(f"RETRIEVED top-{args.k}:")
    for i, r in enumerate(retrieved, start=1):
        desc = (r.description or "").splitlines()[0][:90]
        print(f"  {i}. {r.cve_id}  {desc}")
    print()

    answer = researcher.answer(prompt)
    print(f"AGENT ANSWER (confident={answer.confident}):")
    print(answer.text)
    print()
    print(f"AGENT cves_mentioned: {answer.cves_mentioned}")
    print(f"AGENT citations: {[(c.cve_id, c.url) for c in answer.citations]}")
    print()

    if args.judge:
        from oubliette_warden.agents.research.eval_judge import (
            LLMJudge,
            OllamaJudgeAdapter,
        )
        from oubliette_warden.agents.research.ollama_backend import OllamaTransport

        judge = LLMJudge(
            OllamaJudgeAdapter(
                model=args.judge_model or args.gen_model,
                transport=OllamaTransport(base_url=args.ollama_url),
            )
        )
        verdict = judge.grade(item, answer.text)
        print(f"JUDGE: {'PASS' if verdict.passed else 'FAIL'} — {verdict.reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
