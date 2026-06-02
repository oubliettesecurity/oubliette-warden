"""LLM-judge grader for the Researcher eval (v1 methodology).

The v0 grader used exact keyword-substring matching. That is brittle: it
fails a correct answer that paraphrases ("apply the vendor patch" vs the
literal "upgrade to 2.17"), and it cannot tell a genuine refusal from a
wrong answer. The UK AISI inspect_evals review of an earlier Oubliette
submission flagged exactly this — "pattern matching is the wrong approach
... use an LLM grader."

``LLMJudge`` grades each item semantically against a rubric built from the
item's expected facts. It is instructed to:

  - PASS an answer that correctly addresses the question even if worded
    differently from the rubric,
  - NOT require facts the corpus could not supply (no penalty for omitting
    an ATT&CK id that isn't in an NVD/KEV record),
  - FAIL hallucinations, wrong CVEs, and non-answers.

The judge runs on an Ollama model (ideally a *stronger* model than the one
under test, to avoid grading bias). Output is parsed for a leading
PASS/FAIL verdict; anything else is treated as FAIL with the raw text as
the reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

VERDICT_RE = re.compile(r"\b(PASS|FAIL)\b", re.IGNORECASE)


class JudgeLLM(Protocol):
    """Anything that can complete a single prompt — e.g. OllamaLanguageModel
    exposes ``synthesize``; the judge uses a raw completion instead, so we
    accept any callable-ish object with ``.complete(prompt) -> str``.
    """

    def complete(self, prompt: str) -> str: ...


JUDGE_SYSTEM_PROMPT = """You are grading a vulnerability-research assistant's answer.

Decide whether the ANSWER correctly addresses the QUESTION, using the
RUBRIC as the ground truth of what a correct answer must convey.

WHAT MAKES AN ANSWER PASS:
- Accept paraphrases. Semantic correctness matters, not exact wording.
- For an identification question, naming any CVE in the rubric's accepted
  list (with citation) is sufficient — secondary details may be thin.
- For an exploitability/mitigation question, conveying the substance of
  any one of the rubric's expected_keywords (paraphrased) is sufficient.
- The assistant only has access to NVD + CISA KEV records. Do NOT penalize
  it for omitting facts those sources do not carry (e.g. specific ATT&CK
  technique ids, vendor advisory minutiae).

WHAT MAKES AN ANSWER FAIL:
- Names a CVE that is NOT in the rubric's accepted list (a wrong CVE).
- Invents a fact that contradicts the rubric.
- Declines to answer when the rubric is clearly answerable.

MITRE ATT&CK TECHNIQUE IDs ARE SUPPLEMENTARY — NEVER FAIL ON THEM:
- NVD and CISA KEV records do not contain ATT&CK technique mappings.
- If the rubric lists ATT&CK technique ids, they are background context
  only and MUST NOT be a gating requirement.
- If the model emits ATT&CK technique ids that don't match the rubric,
  that is also acceptable — neither the model nor the corpus is the
  authoritative ATT&CK source.
- Wrong-ATT&CK-id alone is NEVER sufficient grounds to FAIL. Only the
  CVE / factual claim / clear refusal rules above can fail an answer.

Respond with a single line beginning with PASS or FAIL, then a brief
reason. Examples:
PASS — correctly identifies CVE-2021-44228 as Log4Shell with citation.
FAIL — names CVE-2099-0001, which is not in the rubric.
PASS — paraphrases the rubric mitigation; ATT&CK mismatch ignored.
"""


@dataclass
class JudgeResult:
    passed: bool
    reason: str


class LLMJudge:
    def __init__(self, llm: JudgeLLM) -> None:
        self._llm = llm

    def grade(self, item: dict[str, Any], answer_text: str) -> JudgeResult:
        prompt = self._build_prompt(item, answer_text)
        raw = self._llm.complete(prompt).strip()
        m = VERDICT_RE.search(raw)
        if not m:
            return JudgeResult(passed=False, reason=f"unparseable judge output: {raw[:160]!r}")
        passed = m.group(1).upper() == "PASS"
        return JudgeResult(passed=passed, reason=raw[:240])

    @staticmethod
    def _build_prompt(item: dict[str, Any], answer_text: str) -> str:
        rubric_bits: list[str] = []
        # Accept any CVE in `expected_cves` (plural) when present — this is
        # how v1 handles documented sibling/cluster CVEs (PrintNightmare
        # 1675/34527, vCenter pre-auth cluster) without gaming the score.
        ecs = item.get("expected_cves") or (
            [item["expected_cve"]] if item.get("expected_cve") else []
        )
        if ecs:
            rubric_bits.append(
                "Correct CVE — any of these is acceptable: " + ", ".join(ecs)
            )
        if item.get("chained_with"):
            rubric_bits.append(f"Chained with: {item['chained_with']}")
        kws = item.get("expected_keywords") or item.get("rationale_keywords")
        if kws:
            rubric_bits.append(f"Should convey (any of, paraphrase OK): {kws}")
        if item.get("expected_attck"):
            rubric_bits.append(
                f"ATT&CK technique(s) (supplementary, do not require): "
                f"{item['expected_attck']}"
            )
        rubric = "\n".join(f"- {b}" for b in rubric_bits) or "- (none specified)"

        return (
            f"{JUDGE_SYSTEM_PROMPT}\n\n"
            f"QUESTION:\n{item.get('prompt', '').strip()}\n\n"
            f"RUBRIC:\n{rubric}\n\n"
            f"ANSWER:\n{answer_text.strip()}\n\n"
            f"Verdict:"
        )


class OllamaJudgeAdapter:
    """Adapt an OllamaLanguageModel-style transport into a JudgeLLM.

    Reuses the generation endpoint with a plain prompt (no retrieval
    context) — the judge only needs the prompt we build.
    """

    def __init__(self, *, model: str, transport: Any) -> None:
        self._model = model
        self._transport = transport

    def complete(self, prompt: str) -> str:
        body = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 200},
        }
        result = self._transport.post("/api/generate", body)
        text = result.get("response", "")
        return text if isinstance(text, str) else ""
