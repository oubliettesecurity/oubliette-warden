# Oubliette Warden

**Safety-gated, human-on-the-loop multi-agent framework for authorized cyber operations.**

Oubliette Warden coordinates a team of AI agents to run authorized defensive cyber and
penetration-testing workflows end to end — planning, reconnaissance/analysis, code generation
& execution, and vulnerability research — with **every tool invocation gated by the Oubliette
Shield safety pipeline** and **every action reviewable by a human operator before it runs**.

> *Part of the Oubliette platform — Shield defends · Dungeon attacks · Trap traps · **Warden operates.***

## ⚠️ Authorized use only
Warden can drive real offensive tooling (e.g. nmap, Metasploit). It is intended **solely for
authorized security testing** on systems you own or are explicitly contracted to assess. Use is
gated by a mandatory safety pipeline and human approval. Operating it against systems without
authorization may violate the CFAA and other laws. Commercial licensing is sold under terms that
require authorized-use attestation.

## The agents
- **Planner** — turns a high-level objective into an ATT&CK-aligned task graph.
- **Cyber Analysis** — ingests scan/recon output (e.g. Nmap XML) into ranked, evidence-backed findings.
- **Code Generation & Execution** — emits parameterized tool invocations (nmap / Metasploit); **every command passes the Shield safety gate** before it runs, inside an emulated range (e.g. MITRE CALDERA).
- **Vulnerability Research** — citation-bound RAG over an NVD corpus with evidence-integrity enforcement.
- **Operator UI** — human-on-the-loop review/approve/reject of every agent action, with an audit trail.

## Install
```bash
pip install oubliette-warden               # core
pip install "oubliette-warden[research]"   # + RAG research backends (Qdrant, Ollama)
```

## Quickstart

Plan, then see what the safety pipeline would decide — before anything runs:

```bash
oubliette-warden plan --intent "scan for vulnerabilities on 10.50.0.0/24" -o plan.json
oubliette-warden gate --plan plan.json
```

`plan` writes a task graph you can read, edit, diff, and keep. Tasks are emitted
**unapproved**, so a fresh plan does not run:

```
  recon-2e50cb95   DENY   nmap -sV -sC --script default ... 10.50.0.0/24
                          - off-plan: task not in human-approved baseline
  ...
  0 of 3 executable task(s) would proceed; 3 blocked; 1 node(s) have no command.
  Nothing was executed.
```

`gate` **never executes anything** — it exists so an operator sees the decision
before a command touches a target. It exits non-zero when the plan would not
run, so CI and scripts can branch on it.

`--approve-all` answers "would this plan be sound if approved?". Those approvals
are local what-if only and grant nothing; real approval is an operator record in
the review queue.

```bash
oubliette-warden serve            # review/audit API
oubliette-warden demo             # the original screencast narrative
```

There is deliberately no `run` command yet: real execution needs an agreed
policy for which adapters may run in which environment, and inventing that
quietly is how a safety-gated framework grows an ungated path.

## Safety model
1. The CodeGen agent never executes directly — it proposes a command.
2. The command passes the **5-stage safety pipeline**, with `plan_consistency`
   running first and **failing closed**: a command carrying no plan attribution
   is denied as unattributable, so nothing executes outside an approved plan.
3. A **human operator** approves it in the Operator UI before execution.
4. Execution is confined to an authorized/emulated target; everything is audit-logged and replayable.

That guarantee holds on the default pipeline. `evaluate(pipeline=[...])`
composes an explicit pipeline and bypasses the attribution stage by design (used
by unit tests targeting downstream stages); it logs a warning rather than
silently changing behaviour, and no production caller does it.

## License
Apache-2.0 (code). Commercial/Enterprise licensing and authorized-use terms via oubliettesecurity.com.
