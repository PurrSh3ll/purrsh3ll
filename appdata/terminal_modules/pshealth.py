#!/usr/bin/env python3
"""
pshealth.py — dependency health-check for PurrSh3ll (terminal command).

Renders, for the terminal, the same probe the app runs at startup
(core/health_check.py): external tools, optional Python libraries and
runtime paths the app relies on. Read-only — nothing is installed or changed.

Exit code: 0 if everything is present, 1 if anything is missing (scriptable),
2 if the health-check module could not be loaded.
"""

import json as _json
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.dirname(os.path.dirname(_HERE))   # App_beta project root
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

try:
    from core.health_check import run_health_check, _TOOLS, _TERMINALS, _LIBS
except Exception as e:  # module missing / run outside project
    sys.stderr.write(f"pshealth: cannot load health-check module: {e}\n")
    sys.exit(2)

# ── ANSI (disabled when not a TTY or NO_COLOR is set) ─────────────────────────
_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_G   = "\033[32m" if _color else ""
_R   = "\033[31m" if _color else ""
_DIM = "\033[90m" if _color else ""
_B   = "\033[1m"  if _color else ""
_C   = "\033[36m" if _color else ""
_N   = "\033[0m"  if _color else ""
_OK  = f"{_G}✓{_N}" if _color else "[ok]"
_NO  = f"{_R}✗{_N}" if _color else "[--]"

_HELP = """pshealth — check PurrSh3ll external dependencies

USAGE
  pshealth            status of tools, libraries and runtime paths
  pshealth --json     machine-readable JSON (for scripts)
  pshealth -h         this help

EXIT CODE
  0  all present   ·   1  something missing"""


def _row(ok: bool, name: str, why: str) -> str:
    mark = _OK if ok else _NO
    note = "" if ok else f"  {_DIM}— {why}{_N}"
    return f"  {mark} {name:<12}{note}"


def main() -> int:
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(_HELP)
        return 0

    res = run_health_check(_BASE)

    if "--json" in args:
        print(_json.dumps(res, indent=2))
        return 1 if res["missing"] else 0

    found_term = next((t for t in _TERMINALS if shutil.which(t)), None)

    print(f"\n{_B}{_C}PurrSh3ll — health check{_N}\n")

    print(f"{_B}System tools{_N}")
    for name, why in _TOOLS:
        print(_row(res["tools"][name], name, why))
    tname = f"terminal ({found_term})" if found_term else "terminal"
    print(_row(res["terminal"], tname, "no terminal emulator to launch external terminals"))

    print(f"\n{_B}Python libraries{_N}")
    for name, why in _LIBS:
        print(_row(res["libs"][name], name, why))

    print(f"\n{_B}Paths{_N}")
    for label, ok in res["paths"].items():
        print(_row(ok, label, "missing or not writable"))

    total = len(_TOOLS) + 1 + len(_LIBS) + len(res["paths"])
    ok_count = total - len(res["missing"])
    print()
    if res["missing"]:
        print(f"  {_R}{_B}{ok_count}/{total} OK{_N} — degraded: {len(res['missing'])} missing")
        return 1
    print(f"  {_G}{_B}{ok_count}/{total} OK{_N} — all dependencies present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
