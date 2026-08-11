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
import sys
import threading
import time

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
    ("/hack",     "run the auto-hacking loop against a target"),
    ("/target",   "show the recorded hacking-mode target database"),
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
    planning = (mode == "plan")
    use_tools = (not planning) and _supports_tool_loop(p) and _model_has_tools(p, base_dir)
    sys_chars = len(PURRAGENT_SYSTEM) + len(_env_block())
    if planning:
        sys_chars += len(PLAN_MODE_NOTE)     # plan mode swaps the catalog for this
    cat_chars = tools_chars = 0
    if use_tools and mcp is not None:
        try:
            all_tools = mcp.all_tools()
        except Exception:
            all_tools = []
        if all_tools:
            # Catalog is exactly known (sent every prompt); the tools field size
            # varies with what gets surfaced, so budget a fixed reservation.
            cat_chars = len(_DISCOVERY_GUIDE) + len(_catalog_block(all_tools))
            tools_chars = TOOLS_RESERVATION_TOKENS * 4
    custom_chars = len((p.get("custom_system", "") or "").strip())
    hist_chars = sum(len(m.get("content")) for m in history
                     if isinstance(m.get("content"), str))

    fixed = [
        ("system prompt&env",       sys_chars),
        ("tool catalog",            cat_chars),
        ("custom instructions",     custom_chars),
        ("mcp tools (reserved)",    tools_chars),
    ]
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

    # recent conversation vs summarized share the pool left after findings. While
    # the conversation fits, recent stays fully verbatim and *borrows* summary's
    # (and findings') unused space. Once it overflows, summary reclaims its reserved
    # space (up to its cap) to hold the spilled older turns and recent keeps the
    # rest — recent+summary == the available pool, so it never pushes total context
    # past the budget. (Real summarisation isn't wired; this only accounts tokens.)
    if pool is not None:
        avail = max(0, pool - findings_chars)
        summ_reserve = int(SUMMARIZED_CAP_FRAC * pool)
        if hist_chars <= avail:
            recent_chars, summarized_chars = hist_chars, 0
        else:
            recent_chars = max(0, avail - summ_reserve)
            summarized_chars = min(hist_chars - recent_chars, summ_reserve)
    else:
        recent_chars, summarized_chars = hist_chars, 0
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
                 hide_thinking: bool = False) -> dict:
    """Stream one /chat/completions turn (SSE). Prints content deltas live via
    on_text(piece); accumulates tool_call deltas. Reasoning deltas drive a
    'thinking…' spinner when hide_thinking is set, or print greyed inline when
    not. Returns an assistant message dict {content, tool_calls}."""
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

    with resp:
        for raw in resp:                       # SSE: one "data: {json}" per line
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
            if reasoning:
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
    line = Text("  ⚠ enable hacking mode?", style="yellow")
    line.append("  authorised offensive engagement against a target you specify.",
                style="bright_black")
    console.print(line)
    try:
        ans = input("      enable? [y/N] ").strip().lower()
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
    label, _hint, code = goal
    console.print(Text(f"  🎯 objective: {label}", style=f"bold {VIOLET}"))
    console.print()
    # Static English announcement — no LLM (small models are unreliable at this).
    console.print(Text(_HACK_ANNOUNCEMENT, style=VIOLET))
    off = Text("  ", style="bright_black")
    off.append("/hack", style="cyan")
    off.append(" again to turn hacking mode off", style="bright_black")
    console.print(off)
    console.print()
    console.print(Text("  step 1 — enter the target IP:", style="bright_black"))
    console.print()
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

    # Short summary of what went into the DB.
    console.print()
    console.print(Text("  recorded to the target database:", style="bold"))
    console.print(Text(f"    ip:         {ip}", style="bright_black"))
    console.print(Text("    ports:      "
                       + (", ".join(str(p) for p in ports) if ports else "(none)"),
                       style="bright_black"))
    console.print(Text(f"    objective:  {goal}", style="bright_black"))
    console.print()

    # Confirm before starting the engagement.
    try:
        ans = input(f"  start hacking with objective '{goal}'? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans in ("y", "yes"):
        _start_hacking(base_dir, goal)
    else:
        hint = Text("      not started — use ", style="bright_black")
        hint.append("/target", style="cyan")
        hint.append(" to review, ", style="bright_black")
        hint.append("/start", style="cyan")
        hint.append(" to begin", style="bright_black")
        console.print(hint)
    return True


def _start_hacking(base_dir: str, goal) -> None:
    """Begin the engagement on the recorded target: name the target + objective and
    tell the user they can `btw <question>` the model at any time. The actual hacking
    loop runs here (to be implemented). Called from the intake confirm and /start."""
    hosts = purragent_db.fetch_hosts(base_dir)
    target = _host_label(hosts[0]) if hosts else "?"
    console.print(Text(f"  ▸ starting engagement on {target}  ·  objective: {goal}",
                       style=f"bold {VIOLET}"))
    hint = Text("    the hacking loop runs here — use ", style="bright_black")
    hint.append("btw <question>", style="cyan")
    hint.append(" to ask the model about the target anytime", style="bright_black")
    console.print(hint)


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
    can reason about the target without acting on the system."""
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

    def _on_text(piece):
        sys.stdout.write(piece)
        sys.stdout.flush()

    try:
        _chat_stream(endpoint, api_key, body, _on_text,
                     hide_thinking=bool(profile.get("hide_thinking", False)))
        sys.stdout.write("\n")
        sys.stdout.flush()
    except (KeyboardInterrupt, SystemExit):
        # Ctrl-C cancels the btw answer and returns to the prompt (like chat) — it
        # must NOT exit purragent (psai streamers sys.exit(130) on Ctrl-C).
        sys.stdout.write("\n")
        sys.stdout.flush()
        console.print("  [dim]interrupted[/dim]")
    except Exception as e:
        console.print(f"  [red]btw failed:[/red] [dim]{e}[/dim]")


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
    for nt in notes:
        txt = " ".join((nt.get("text") or "").split())
        if len(txt) > 100:
            txt = txt[:100] + "…"
        parts.append(Text(f"    · {nt.get('kind')}: {txt}", style="bright_black"))
    if not (creds or eps or notes):
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


def query_model_with_tools(profile: dict, base_dir: str, history: list,
                           mcp: "mcp_client.MCPManager", on_event, on_text,
                           mode: str = "auto", on_confirm=None,
                           offer_hack: bool = False, on_hack=None) -> str:
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

    all_tools = mcp.all_tools()
    retriever = _get_retriever(base_dir, all_tools)
    discovery = retriever is not None      # False → fall back to sending all schemas

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if planning:
        sys_parts.append(PLAN_MODE_NOTE)
    elif discovery:
        sys_parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
    if offer_hack and not planning:
        sys_parts.append(_HACK_TRIGGER_GUIDE)
    if custom_system:
        sys_parts.append(custom_system)
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

    def ensure_mcp() -> None:
        if not mcp.connected:
            mcp.connect()

    # Connect up front (cheap: stdio spawn + cached HTTP tools, no network) so
    # /context, model capabilities and the tool loop all reflect the enabled MCP
    # servers immediately — without needing a first prompt or opening /mcp.
    ensure_mcp()

    def toolbar():
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
        if not p:
            return HTML("  <style fg='#e5c07b'>no model</style> — type "
                        "<style fg='#61afef'>/model</style> to choose   "
                        f"{mode_seg}   {priv_seg}{dbg_seg}{hack_seg}   "
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
            f"{priv_seg}{dbg_seg}{hack_seg}   <style fg='#7f7f7f'>/exit to quit</style>")

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
            # /start is offered only while hacking mode is on.
            extra_provider=lambda: ([("/start", "start hacking the recorded target")]
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
            else:
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
            elif cmd == "/hack":
                if hack_mode:
                    # Already on → /hack again offers to turn it off.
                    console.print(Text("  ⚠ disable hacking mode?", style="yellow"))
                    try:
                        ans = input("      disable? [y/N] ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        ans = ""
                    if ans in ("y", "yes"):
                        hack_mode = False
                        hack_goal = None
                        awaiting_target = False
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
            elif cmd == "/target":
                # Deleting the last target in /target re-arms the target-IP prompt
                # (only meaningful while hacking mode is on).
                if _db_view(base_dir) and hack_mode:
                    awaiting_target = True
                    conversation_started = True
                    console.print(Text("  step 1 — enter the target IP:",
                                       style="bright_black"))
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
                    _start_hacking(base_dir, hack_goal)
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
        # with the target database injected as context. The hacking loop (to be
        # implemented) runs alongside; btw lets you ask about the target meanwhile.
        if hack_mode and text.split(" ", 1)[0].lower() == "btw":
            conversation_started = True
            q = text.split(" ", 1)[1].strip() if " " in text else ""
            if q:
                _btw(ctx, base_dir, q)
            else:
                console.print("  [dim]usage:[/dim] btw <question>")
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

        # Pre-flight guard: if the request would overflow the model's context window
        # (a too-small /setcontext, or a genuinely large history/param), don't send
        # it — a blown window truncates or errors mid-generation. Warn and point at
        # /context and /setcontext. (No real summarisation yet, so the whole history
        # is sent verbatim; this catches the overflow before it reaches the model.)
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
                                               on_hack=_on_hack)
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
                            offer_hack=False)
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
