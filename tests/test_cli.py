"""The operator CLI.

Warden's console script used to be the screencast runner: one positional
intent string that printed four demo shots. That is a fine demo and a
non-existent product surface — you could not persist a plan, review it, or gate
it from a terminal, which is what an operator actually needs to do.

The safety property these tests defend is narrow and absolute: **`gate` never
executes anything.** It exists so an operator can see what the pipeline would
decide before any command touches a target, and a gate command that quietly
ran something would be worse than no command at all. Several tests below install
adapters whose `execute()` raises, so an accidental execution fails loudly
rather than passing silently.
"""

from __future__ import annotations

import io
import json

import pytest

from oubliette_warden import cli
from oubliette_warden.agents.codegen.base import ExecutionEnv

#: Single-phase: one recon task, no edges. The smallest real plan.
INTENT = "enumerate hosts on 10.50.0.0/24"

#: Four phases (recon -> service_version -> vuln_enum -> research) with three
#: ordering edges and one non-executable node. Anything about ordering or
#: research handoffs must use this one; the enumerate intent produces neither.
FULL_INTENT = "scan for vulnerabilities on 10.50.0.0/24"


def run(args, **kw):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(args, stdout=out, stderr=err, **kw)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def plan_file(tmp_path):
    path = tmp_path / "plan.json"
    code, _, err = run(["plan", "--intent", INTENT, "-o", str(path)])
    assert code == 0, err
    return path


@pytest.fixture
def full_plan_file(tmp_path):
    """A plan with ordering edges and a non-executable research node."""
    path = tmp_path / "full.json"
    code, _, err = run(["plan", "--intent", FULL_INTENT, "-o", str(path)])
    assert code == 0, err
    return path


# --- basics -----------------------------------------------------------------


def test_version_reports_the_distribution_version():
    code, out, _ = run(["version"])
    assert code == 0
    assert "warden" in out.lower()


def test_no_arguments_prints_help_and_does_not_fail():
    code, out, _ = run([])
    assert code == 0
    assert "plan" in out and "gate" in out


def test_unknown_subcommand_is_an_error():
    with pytest.raises(SystemExit) as ei:
        run(["nonesuch"])
    assert ei.value.code != 0


# --- plan --------------------------------------------------------------------


def test_plan_emits_a_task_graph_as_json(plan_file):
    data = json.loads(plan_file.read_text(encoding="utf-8"))
    assert data["intent"] == INTENT
    assert data["target_scope"] == ["10.50.0.0/24"]
    assert data["nodes"], "a plan with no tasks is not a plan"
    assert all("task_id" in n for n in data["nodes"])


def test_planned_tasks_start_unapproved(plan_file):
    """Anchored plan_trust denies non-approved tasks. A planner that emitted
    pre-approved tasks would defeat the entire posture."""
    data = json.loads(plan_file.read_text(encoding="utf-8"))
    assert all(n["operator_approved"] is False for n in data["nodes"])


def test_plan_round_trips_through_disk(plan_file):
    """gate consumes what plan produced; the two must agree on the graph."""
    graph = cli.load_plan(plan_file)
    reserialised = cli.plan_to_dict(graph)
    assert reserialised == json.loads(plan_file.read_text(encoding="utf-8"))
    assert [t.task_id for t in graph.topological_order()]


def test_plan_preserves_edges_so_ordering_survives(full_plan_file):
    graph = cli.load_plan(full_plan_file)
    assert graph.edges, "ordering edges must survive serialisation"
    order = [t.task_id for t in graph.topological_order()]
    for edge in graph.edges:
        assert order.index(edge.before) < order.index(edge.after)


def test_plan_without_a_derivable_scope_fails_cleanly(tmp_path):
    code, _, err = run(["plan", "--intent", "do something vague", "-o", str(tmp_path / "p.json")])
    assert code != 0
    assert "scope" in err.lower()
    assert not (tmp_path / "p.json").exists()


def test_explicit_scope_overrides_extraction(tmp_path):
    path = tmp_path / "p.json"
    code, _, err = run(["plan", "--intent", "sweep the lab", "--scope", "10.9.0.0/24", "-o", str(path)])
    assert code == 0, err
    assert json.loads(path.read_text(encoding="utf-8"))["target_scope"] == ["10.9.0.0/24"]


# --- gate: the load-bearing safety property ---------------------------------


class ExplodingAdapter:
    """Any execution at all is a test failure."""

    name = "exploding"

    def __init__(self, inner):
        self._inner = inner
        self.name = inner.name

    def plan(self, task):
        return self._inner.plan(task)

    def execute(self, cmd, env):  # pragma: no cover - must never run
        raise AssertionError("gate executed a command; it must only evaluate")


def _no_execution_resolver(task):
    inner = cli.default_adapter_for(task)
    return ExplodingAdapter(inner) if inner is not None else None


def test_gate_never_executes_anything(plan_file):
    code, out, err = run(["gate", "--plan", str(plan_file)], adapter_for=_no_execution_resolver)
    assert code in (0, 1), err
    assert out, "gate produced no report"


def test_gate_denies_unapproved_tasks(plan_file):
    """Anchored posture, visible from the terminal: a fresh plan does not run."""
    code, out, _ = run(["gate", "--plan", str(plan_file), "-f", "json"])
    report = json.loads(out)
    verdicts = {t["task_id"]: t["verdict"] for t in report["tasks"] if t["verdict"]}
    assert verdicts, "expected gated tasks"
    assert all(v == "DENY" for v in verdicts.values()), verdicts
    assert code == 1, "a plan that cannot run must not report success"


def test_gate_reports_the_reason_not_just_the_verdict(plan_file):
    _, out, _ = run(["gate", "--plan", str(plan_file), "-f", "json"])
    report = json.loads(out)
    gated = [t for t in report["tasks"] if t["verdict"]]
    assert all(t["reasons"] for t in gated)


def test_approving_tasks_changes_the_outcome(plan_file):
    """The what-if path. Without it the command can only ever say DENY, which
    tells an operator nothing about whether the plan is otherwise sound."""
    _, before_out, _ = run(["gate", "--plan", str(plan_file), "-f", "json"])
    _, after_out, _ = run(["gate", "--plan", str(plan_file), "--approve-all", "-f", "json"])

    before = {t["task_id"]: t["verdict"] for t in json.loads(before_out)["tasks"]}
    after = {t["task_id"]: t["verdict"] for t in json.loads(after_out)["tasks"]}

    assert set(before) == set(after), "the same tasks must be reported either way"
    assert {v for v in before.values() if v} == {"DENY"}
    assert before != after, "approving every task changed nothing"
    assert json.loads(after_out)["approved_locally"] is True
    assert json.loads(before_out)["approved_locally"] is False


def test_approval_is_labelled_as_local_not_an_operator_record(plan_file):
    """--approve-all must not read as a real approval from the review queue."""
    _, out, _ = run(["gate", "--plan", str(plan_file), "--approve-all"])
    assert "local" in out.lower() or "what-if" in out.lower()


def test_research_nodes_are_reported_as_having_no_command(full_plan_file):
    _, out, _ = run(["gate", "--plan", str(full_plan_file), "-f", "json"])
    report = json.loads(out)
    no_command = [t for t in report["tasks"] if t["verdict"] is None]
    assert no_command, "expected a non-executable node in this plan"
    assert all(t["phase"] == "research" for t in no_command)
    assert all(t["note"] for t in no_command), "a skipped node must say why"


def test_a_blocked_task_does_not_satisfy_a_successors_ordering(full_plan_file):
    """Every task is unapproved, so the first DENYs and nothing after it may
    claim its predecessor completed. A report that showed later tasks as
    approved would be telling the operator this plan runs when it stalls."""
    _, out, _ = run(["gate", "--plan", str(full_plan_file), "-f", "json"])
    executable = [t for t in json.loads(out)["tasks"] if t["verdict"]]
    assert executable
    assert all(t["verdict"] == "DENY" for t in executable)


def test_gate_on_a_missing_plan_fails_cleanly(tmp_path):
    code, _, err = run(["gate", "--plan", str(tmp_path / "absent.json")])
    assert code != 0
    assert "not found" in err.lower() or "no such" in err.lower()


def test_gate_on_a_malformed_plan_fails_cleanly(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, _, err = run(["gate", "--plan", str(path)])
    assert code != 0
    assert err.strip()


# --- adapter registry --------------------------------------------------------


def test_every_executable_phase_resolves_to_an_adapter(plan_file):
    """A phase with no adapter silently does nothing, which looks like success."""
    graph = cli.load_plan(plan_file)
    for task in graph.topological_order():
        phase = task.metadata.get("phase")
        adapter = cli.default_adapter_for(task)
        if phase == "research":
            assert adapter is None
        else:
            assert adapter is not None, f"phase {phase!r} resolves to no adapter"


def test_registry_covers_every_phase_the_planner_can_emit():
    """Pins the registry against the planner rather than against this test."""
    from oubliette_warden.agents.codegen.base import Task

    for phase in cli.PHASE_ADAPTERS:
        task = Task(task_id="t", intent="i", target_scope=["10.0.0.0/24"],
                    metadata={"phase": phase})
        cli.default_adapter_for(task)  # must not raise


def test_an_unknown_phase_does_not_silently_skip():
    from oubliette_warden.agents.codegen.base import Task

    task = Task(task_id="t", intent="i", target_scope=["10.0.0.0/24"],
                metadata={"phase": "teleport"})
    with pytest.raises(cli.CLIError, match="teleport"):
        cli.default_adapter_for(task)


# --- env selection -----------------------------------------------------------


def test_default_execution_env_is_the_contained_one(plan_file):
    _, out, _ = run(["gate", "--plan", str(plan_file), "-f", "json"])
    assert json.loads(out)["env"] == ExecutionEnv.CALDERA_ONLY.value
