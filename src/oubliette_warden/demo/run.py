"""Master demo runner — runs shots 2–5 in sequence with banner separators.

Usage:
    python -m oubliette_warden.demo.run

Produces one continuous on-screen narrative the screencast can capture
in a single take. For shots 6–7 (the Operator UI), launch
``python -m oubliette_warden.demo.ui`` separately and switch to a browser tab.
"""

from __future__ import annotations

import sys

from . import analyze, codegen, gate, plan


def _banner(label: str) -> None:
    bar = "=" * 64
    print()
    print(bar)
    print(f"  {label}")
    print(bar)


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    intent = args[0] if args else "enumerate hosts on 10.50.0.0/24"

    _banner(f"SHOT 2 — Project Management agent emits task graph")
    plan.main([intent])

    _banner(f"SHOT 3 — Code Generation agent emits Nmap command")
    codegen.main([intent])

    _banner(f"SHOT 4 — Five-stage safety pipeline gates the command")
    gate.main([intent])

    _banner(f"SHOT 5 — Cyber Analysis agent ranks findings")
    analyze.main([])

    print()
    print("=" * 64)
    print("  Next: launch shots 6-7")
    print("  $ python -m oubliette_warden.demo.ui")
    print("  Then browse to http://127.0.0.1:8000/reviews and /audit")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
