# CRIT-1 — Wiring `plan_consistency` into the runtime safety gate (design proposal)

**Date:** 2026-07-20
**Status:** Proposal — needs owner decision before implementation
**Severity:** CRITICAL (2026-07-19 security scan). The containment claim the framework advertises is not enforced in production.

## 1. The problem

The `plan_consistency` verifier — the stage that enforces "the command maps to a real, human-approved, correctly-ordered planned task" — **exists and is tested but never runs in production.**

- `DEFAULT_PIPELINE` (`agents/codegen/safety_gate.py:136`) = `[_stage_pre_filter, _stage_pattern_detector, _stage_rag_guard, _stage_llm_judge, _stage_mcp_guard]`. No plan_consistency.
- The runtime enforcement path is `CommandAdapter._gate_or_raise` (`base.py:129`) → `safety_gate.evaluate(command, env)` (`safety_gate.py:145`) → falls through to `DEFAULT_PIPELINE`.
- The verifier is a **factory**: `make_plan_consistency_stage(plan: TaskGraph, current_task_id: str, completed_task_ids: set[str], config)` (`plan_consistency.py:115`). It closes over the plan graph, the current task id, and the completed-task set to check attributability, anchored plan-trust, and predecessor ordering.

**Why it can't just be appended to `DEFAULT_PIPELINE`:** a `StageFn` is `Callable[[Command, ExecutionEnv], StageResult]` (`safety_gate.py:50`). The stage needs `(plan, current_task_id, completed_task_ids)` — none of which the runtime carries:
- `Command` (`base.py:63`) has no `task_id` and no plan reference. The adapter's `plan(task: Task) -> Command` receives the `Task` (which *does* have `task_id`, `operator_approved`, etc. — `base.py:50`) but drops that linkage; the emitted `Command` cannot be attributed back to its task.
- `evaluate(cmd, env, pipeline=None)` receives no plan/task context, and neither does the adapter's `execute(command, env)`.

So the verifier has nothing to verify against at the point of enforcement. This is a plumbing/design gap, not a one-line wiring fix.

## 2. Design decision required

The core decision is **how to thread task/plan context to the gate, and what happens when it's absent.** Absent-context behavior is the load-bearing choice: if plan_consistency silently no-ops when context is missing, adding it to the pipeline creates a bypass (worse than today, because it looks enforced). It must **fail closed** — consistent with the CRIT-3 decision already taken (llm_judge → ESCALATE).

## 3. Recommended approach

**(a) Give `Command` its task linkage.** Add `task_id: str` to `Command` (`base.py:63`), populated by each adapter's `plan(task)` from `task.task_id`. Cheap, and it makes every command attributable. (The whole `TaskGraph` should NOT live on each Command — only the id.)

**(b) Carry plan + completed-set on the execution session, not the command.** `CommandAdapter` already holds an optional `_review_queue` set in `__init__` (`base.py:101`). Add a parallel optional `_gate_context` holding `(plan: TaskGraph, completed_task_ids: set[str])` for the current run, set by the CodeGen orchestrator that owns the plan and tracks completion.

**(c) Thread context into `evaluate`.** Change to `evaluate(cmd, env, pipeline=None, *, context: GateContext | None = None)`. Build the default pipeline dynamically: when `context` is present, insert `make_plan_consistency_stage(context.plan, cmd.task_id, context.completed_task_ids)` as the FIRST stage (attributability should gate before anything else). `_gate_or_raise` passes `self._gate_context` through.

**(d) Fail closed on missing context (the decision).** When plan_consistency is in the pipeline but `context is None` or `cmd.task_id == ""`, the stage returns **DENY** ("unattributable: no plan context") rather than being skipped. Consequence: **no command executes without plan attribution.** This is a real behavioral shift — every execution path must now supply plan context or be denied — and it is the intended containment posture. It pairs with CRIT-3's fail-closed llm_judge: together they mean the framework refuses to act on anything it cannot attribute and gate.

## 4. Blast radius / risks

- Every adapter `execute()` path and every caller that runs commands must now supply `_gate_context`. Callers that don't will get DENY. This will surface as broken flows until the orchestrator threads context through — expected, and the point.
- Interacts with CRIT-3: with both fixes, autonomous execution requires (i) plan attribution and (ii) an operator approval for the ESCALATE'd llm_judge. That may be intentional for a containment demo but makes fully-autonomous runs impossible without wiring the plan context AND an approval path. Confirm that's the desired end state.
- `plan_trust == "anchored"` mode additionally requires `task.operator_approved == True` (`plan_consistency.py:148`); decide whether the default runtime should run anchored or model mode.

## 5. Test plan (TDD)

- Integration: a command with valid context (in-plan, operator-approved task, predecessors complete) → APPROVE through `DEFAULT_PIPELINE`.
- Fail-closed: same command with `context=None` or empty `task_id` → DENY.
- Off-plan: `task_id` not in plan → DENY; unapproved task in anchored mode → DENY; missing predecessor → DENY.
- Regression: existing `tests/test_plan_consistency.py` (unit-level stage) stays green; existing pipeline tests updated for the new first stage.

## 6. Recommendation

Proceed with §3 as a dedicated PR **after** the CRIT-2/CRIT-3 branch merges (keep the fail-closed changes reviewable in isolation). Estimated scope: `Command` field + `GateContext` + `evaluate` signature + orchestrator threading + ~6 tests. The only open decision that needs owner sign-off is §3(d)/§4: confirming the fail-closed-on-missing-context posture and the anchored-vs-model default, given it makes attribution mandatory for all execution.
