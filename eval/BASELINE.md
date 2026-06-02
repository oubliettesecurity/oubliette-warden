# Researcher eval baseline (stub backend)

The Phase I §2 Objective 5 acceptance threshold is **≥80%** on `researcher_eval_v0.yaml` (50 items). That target presumes a real LLM (Ollama-hosted local model) and a real Qdrant index over the full NIST NVD corpus.

To prove the eval harness itself works correctly *before* the real backend is wired, the same harness is run against deterministic stubs (`stub_backends.CannedRetriever` + `CannedLLM`). The expected baseline:

```
Oubliette Warden Researcher eval — 17/50 (34.00%)
  attck     0/10   ← stub cannot reason about ATT&CK mapping
  chain     5/10   ← partial: id-recall succeeds, multi-step reasoning fails
  exploit   2/10   ← stub cannot integrate context to classify exploitability
  id        10/10  ← stub designed for this — restates top retrieved record
  mitigate  0/10   ← stub cannot synthesize mitigation guidance
```

This is the **correct** baseline. It demonstrates:

1. **Harness works** — id category passes 10/10 because the stub's only competency is exact-match retrieval, and the harness scores that correctly.
2. **Harness is honest** — categories that genuinely require reasoning (exploit / mitigate / attck) score 0–2 because the stub cannot reason. Anything higher would be a bug in the harness, not the agent.
3. **Real lift is well-defined** — the gap from 34% (stub) to 80% (Phase I target) is exactly the four reasoning categories. That gap is closeable with a competent local LLM (Llama 3.x 8B+ or DeepSeek-R1) plus a tightened citation-emission prompt.

## How to reproduce

```bash
cd ~/Projects/oubliette-warden
PYTHONPATH=src python -m oubliette_warden.agents.research.eval_harness --eval eval/researcher_eval_v0.yaml
```

JSON output for CI:

```bash
PYTHONPATH=src python -m oubliette_warden.agents.research.eval_harness --json | jq .
```

Exit code 0 if `score >= --threshold` (default 0.80), 1 otherwise. Phase I CI gates on the real-LLM score, not the stub.
