"""Tests for the LLM-judge grader (v1 eval methodology)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oubliette_warden.agents.research.eval_judge import (  # noqa: E402
    LLMJudge,
    OllamaJudgeAdapter,
)


class FakeJudgeLLM:
    def __init__(self, response: str) -> None:
        self._response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self._response


ITEM = {
    "id": "r-id-001",
    "category": "id",
    "prompt": "A Java logging library RCE via JNDI. Which CVE?",
    "expected_cve": "CVE-2021-44228",
    "expected_keywords": ["Log4Shell", "JNDI"],
}


def test_judge_parses_pass_verdict():
    j = LLMJudge(FakeJudgeLLM("PASS — correctly identifies CVE-2021-44228."))
    r = j.grade(ITEM, "This is CVE-2021-44228, Log4Shell.")
    assert r.passed is True
    assert "CVE-2021-44228" in r.reason


def test_judge_parses_fail_verdict():
    j = LLMJudge(FakeJudgeLLM("FAIL — names the wrong CVE."))
    r = j.grade(ITEM, "This is CVE-1999-0001.")
    assert r.passed is False
    assert "wrong CVE" in r.reason


def test_judge_unparseable_output_is_fail():
    j = LLMJudge(FakeJudgeLLM("I'm not sure how to grade this honestly."))
    r = j.grade(ITEM, "something")
    assert r.passed is False
    assert "unparseable" in r.reason


def test_judge_case_insensitive_verdict():
    j = LLMJudge(FakeJudgeLLM("pass - good enough"))
    r = j.grade(ITEM, "CVE-2021-44228")
    assert r.passed is True


def test_judge_prompt_includes_rubric_and_answer():
    fake = FakeJudgeLLM("PASS")
    j = LLMJudge(fake)
    j.grade(ITEM, "my answer text")
    prompt = fake.prompts[0]
    assert "CVE-2021-44228" in prompt          # rubric
    assert "Log4Shell" in prompt               # expected keyword
    assert "my answer text" in prompt          # the answer
    assert "Java logging library RCE" in prompt  # the question


def test_judge_rubric_accepts_plural_expected_cves():
    fake = FakeJudgeLLM("PASS")
    j = LLMJudge(fake)
    item = {
        "id": "r-id-003",
        "category": "id",
        "prompt": "PrintNightmare?",
        "expected_cve": "CVE-2021-34527",
        "expected_cves": ["CVE-2021-34527", "CVE-2021-1675"],
    }
    j.grade(item, "It's CVE-2021-1675.")
    prompt = fake.prompts[0]
    # Both sibling CVEs must appear in the rubric so the judge knows
    # either is acceptable.
    assert "CVE-2021-34527" in prompt
    assert "CVE-2021-1675" in prompt
    # The rubric phrasing must signal acceptance, not enumeration.
    assert "any of" in prompt.lower() or "acceptable" in prompt.lower()


def test_judge_rubric_falls_back_to_singular_when_no_plural():
    fake = FakeJudgeLLM("PASS")
    j = LLMJudge(fake)
    item = {
        "id": "r-id-001",
        "category": "id",
        "prompt": "Log4Shell?",
        "expected_cve": "CVE-2021-44228",
    }
    j.grade(item, "CVE-2021-44228")
    assert "CVE-2021-44228" in fake.prompts[0]


def test_judge_marks_attck_as_supplementary_not_required():
    fake = FakeJudgeLLM("PASS")
    j = LLMJudge(fake)
    item = {**ITEM, "expected_attck": ["T1190"]}
    j.grade(item, "answer")
    prompt = fake.prompts[0]
    # ATT&CK must be framed as supplementary so the judge doesn't fail an
    # answer for omitting a technique id the corpus can't supply.
    assert "supplementary" in prompt.lower()
    assert "T1190" in prompt


# ----- OllamaJudgeAdapter -----


class FakeTransport:
    def __init__(self, response: dict) -> None:
        self._response = response
        self.posts: list[tuple[str, dict]] = []

    def post(self, path: str, body: dict) -> dict:
        self.posts.append((path, body))
        return self._response


def test_ollama_judge_adapter_uses_generate_with_zero_temp():
    t = FakeTransport({"response": "PASS — ok"})
    adapter = OllamaJudgeAdapter(model="qwen2.5:14b", transport=t)
    out = adapter.complete("grade this")
    assert out == "PASS — ok"
    path, body = t.posts[0]
    assert path == "/api/generate"
    assert body["model"] == "qwen2.5:14b"
    assert body["options"]["temperature"] == 0.0
    assert body["stream"] is False


def test_ollama_judge_adapter_handles_non_string_response():
    t = FakeTransport({"response": None})
    adapter = OllamaJudgeAdapter(model="m", transport=t)
    assert adapter.complete("x") == ""
