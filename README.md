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
```bash
oubliette-warden --help          # run the orchestrated demo workflow
```
Or drive individual agents via `python -m oubliette_warden.demo.{plan,analyze,codegen,gate}`.

## Safety model
1. The CodeGen agent never executes directly — it proposes a command.
2. The command passes the **Shield 5-stage safety pipeline** (blocks unsafe/destructive invocations).
3. A **human operator** approves it in the Operator UI before execution.
4. Execution is confined to an authorized/emulated target; everything is audit-logged and replayable.

## License
Apache-2.0 (code). Commercial/Enterprise licensing and authorized-use terms via oubliettesecurity.com.
