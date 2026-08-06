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
import json
import os
import platform
import shutil
import sys
import time

# Reuse psai's provider/profile/LLM plumbing. psai lives in the same directory;
# importing it is side-effect-free (its main() is guarded by __main__).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psai  # noqa: E402
import mcp_client  # noqa: E402  — dependency-free MCP (Model Context Protocol) client
import tool_retriever  # noqa: E402  — client-side RAG for semantic tool discovery

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
    ("/hack",     "hacking toolkit"),
    ("/upgrade",  "re-launch purragent as root (sudo)"),
    ("/debug",    "toggle showing the raw request sent to the model"),
    ("/greeting", "set the welcome name (e.g. /greeting Neo)"),
    ("/context",  "show how much of the context window is used"),
    ("/setcontext", "set the max context this session (e.g. /setcontext 32k)"),
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

# Agent run modes (Claude-Code-style). Skeleton only for now — selecting a mode
# is remembered but does not change behaviour yet.
DEFAULT_MODE = "confirm"
AGENT_MODES = [
    ("auto",      "run commands automatically, without asking"),
    ("semi-auto", "ask for permission only for risky actions"),
    ("confirm",   "ask before running each command"),
    ("plan",      "plan only — describe actions, don't execute"),
]

# Commands shown in the welcome box's right column (the essentials).
BANNER_COMMANDS = [
    ("/model", "switch model"),
    ("/help",  "show help"),
    ("/exit",  "quit"),
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
    system prompt (+ <env>, + discovery guide & tool catalog when tools are on)
    plus the whole conversation history. An estimate, not an exact tokenizer."""
    parts = [PURRAGENT_SYSTEM, _env_block()]
    if use_tools and mcp is not None:
        try:
            all_tools = mcp.all_tools()
        except Exception:
            all_tools = []
        if all_tools:
            parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
    custom = (profile.get("custom_system", "") or "").strip() if profile else ""
    if custom:
        parts.append(custom)
    for m in history:
        c = m.get("content")
        if isinstance(c, str) and c:
            parts.append(c)
    total_chars = sum(len(p) for p in parts)
    return total_chars // 4


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
    """Pick the agent run mode (skeleton — the choice is inert for now).

    Returns the chosen mode name, or None if cancelled.
    """
    options = [(name, hint) for name, hint in AGENT_MODES]
    default_idx = next((i for i, (n, _) in enumerate(AGENT_MODES)
                        if n == DEFAULT_MODE), 0)
    start = next((i for i, (n, _) in enumerate(AGENT_MODES) if n == current),
                 default_idx)
    choice = select_option("Agent mode", options, start=start)
    if choice is None:
        return None
    return AGENT_MODES[choice][0]


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

    right = Table.grid(padding=(0, 2))
    right.add_column(style="cyan", no_wrap=True)
    right.add_column(style="dim", no_wrap=True)
    right.add_row(Text("Commands", style="bold white"), "")
    for cmd, hint in BANNER_COMMANDS:
        right.add_row(cmd, hint)

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
ENABLE_TIMEOUT = 20.0      # hard cap (s) on a background enable (tool fetch)


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
                    offset = max(0, min(det_off, max_off))
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
# it doesn't burn tool calls discovering the user, home, OS, cwd, etc. Gathered
# from stdlib only (no subprocess), and deliberately WITHOUT any IP/network info.

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
        f"home: {os.path.expanduser('~')}",
        f"os: {os_line}",
        f"shell: {os.environ.get('SHELL', '?')}",
    ])


def _env_block() -> str:
    """The <env> block for the system prompt: cached static facts plus a live
    cwd and date (so long sessions don't show a stale date)."""
    from datetime import date
    live = f"cwd: {os.getcwd()}\ndate: {date.today().isoformat()}"
    return "<env>\n" + _env_facts() + "\n" + live + "\n</env>"


# ── LLM query (reuses psai) ────────────────────────────────────────────────────

def query_model(profile: dict, base_dir: str, history: list) -> str:
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    url      = profile.get("url", "") or psai._DEFAULT_URLS.get(provider, "")
    api_key  = psai._load_api_key(profile.get("name", ""), base_dir)

    custom_params    = psai._parse_custom_params(profile)
    custom_system    = profile.get("custom_system", "").strip()
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking", False))
    temperature      = psai._profile_temperature(profile)

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

META_TOOL_NAME = "request_tool"
_META_TOOL = {
    "type": "function",
    "function": {
        "name": META_TOOL_NAME,
        "description": (
            "Request a tool by describing, in natural language, what you need to "
            "do. The matching tools (with their full parameters) will then be "
            "provided so you can call them. Use this whenever you need to act on "
            "the system — do not guess tool names."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "need": {
                    "type": "string",
                    "description": (
                        "A natural-language description of the action or "
                        "capability you need, e.g. 'scan a host for open ports' "
                        "or 'read a configuration file'."
                    ),
                },
            },
            "required": ["need"],
        },
    },
}

_DISCOVERY_GUIDE = (
    "TOOLS: you can act on the system through tools, but they are not listed "
    "directly. Below is a catalog of the capabilities available to you. To use "
    "one, call the `request_tool` function with a natural-language description of "
    "what you need; the matching tools will then be given to you with their "
    "parameters, and you can call them. If one of the provided tools already fits "
    "the task, call it directly — only call `request_tool` again if none of them "
    "fit. If the task needs no tool, just answer normally."
)


def _catalog_block(all_tools: list) -> str:
    """The always-visible capability catalog (short descriptions only, no tool
    names — the model reaches capabilities via request_tool, not by name)."""
    lines = "\n".join(f"- {t['short']}" for t in all_tools)
    return "<tool_catalog>\n" + lines + "\n</tool_catalog>"


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


def query_model_with_tools(profile: dict, base_dir: str, history: list,
                           mcp: "mcp_client.MCPManager", on_event, on_text) -> str:
    """Run the agent loop and return the model's final text answer.

    `on_event(kind, name, payload)` reports progress: kind is 'call' (payload is
    the arguments dict), 'result' (payload is the MCP result dict), or 'search'
    (a request_tool discovery — payload is {'need', 'hits'}).
    `on_text(piece)` receives streamed answer chunks as they arrive (the final
    answer is streamed live, so the caller should not print the return value).
    """
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    temperature   = psai._profile_temperature(profile)
    custom_params = psai._parse_custom_params(profile)
    custom_system = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    all_tools = mcp.all_tools()
    retriever = _get_retriever(base_dir, all_tools)
    discovery = retriever is not None      # False → fall back to sending all schemas

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if discovery:
        sys_parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
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

    for _round in range(TOOL_LOOP_MAX_ROUNDS):
        offer_meta = discovery and discovery_rounds < DISCOVERY_MAX_ROUNDS
        tools_field = ([_META_TOOL] if offer_meta else []) + list(active.values())

        body = {"model": model, "messages": msgs}
        if tools_field:
            body["tools"] = tools_field
            body["tool_choice"] = "auto"
        if temperature is not None:
            body["temperature"] = temperature
        if custom_params:
            body.update(custom_params)

        message = _chat_stream(endpoint, api_key, body, on_text, hide_thinking)

        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return (message.get("content") or "").strip()

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
    def __init__(self, servers_provider=None):
        # Callable returning [(name, enabled)] for non-built-in MCP servers, for
        # completing "/mcp <enable|disable|remove> <name>". Defaults to none.
        self._servers = servers_provider or (lambda: [])

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
        for cmd, hint in SLASH:
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text),
                                 display=cmd, display_meta=hint)


# ── REPL ───────────────────────────────────────────────────────────────────────

def run_repl(base_dir: str, config: dict, profile: dict | None) -> None:
    ctx = {"profile": profile, "max_context": None}   # max_context: session override
    history: list = []
    _state = _load_state(base_dir)
    greeting = _state.get("greeting") or DEFAULT_GREETING
    mode = _state.get("mode") or DEFAULT_MODE   # skeleton: inert
    debug = False   # /debug: mirror pschat's --debug (dump the request to the model)

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

    def toolbar():
        p = ctx["profile"]
        mode_seg = f"<style fg='#b46cff'>mode: {mode}</style>"
        # Privilege indicator: red 'root' warns you're elevated, dim 'user' otherwise.
        priv_seg = ("<style fg='#ff5f5f'>⚡ root</style>" if _is_root()
                    else "<style fg='#7f7f7f'>user</style>")
        # Only shown while /debug is on, so you always know the request is dumped.
        dbg_seg = "   <style fg='#e5c07b'>debug</style>" if debug else ""
        if not p:
            return HTML("  <style fg='#e5c07b'>no model</style> — type "
                        "<style fg='#61afef'>/model</style> to choose   "
                        f"{mode_seg}   {priv_seg}{dbg_seg}   "
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
            f"{priv_seg}{dbg_seg}   <style fg='#7f7f7f'>/exit to quit</style>")

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
                if not mcp_client.is_builtin_server(s)]),
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
    hint = ("  \x1b[2mtype \x1b[36m/\x1b[0m\x1b[2m for commands · "
            "\x1b[36m/model\x1b[0m\x1b[2m to pick a model · a message to chat\x1b[0m\n")

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
                    console.print(f"  [green]▸[/green] agent mode set to "
                                  f"[bold]{mode}[/bold] "
                                  "[dim](not wired up yet)[/dim]")
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
            elif cmd == "/hack":
                show_view(_skeleton_body(
                    "purragent — hack",
                    "Hacking toolkit — quick offensive-security actions."))
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
                p = ctx["profile"]
                if not p:
                    console.print("  [yellow]No model attached.[/yellow] "
                                  "[dim]/model to choose one[/dim]")
                else:
                    maxc = _effective_max_context(ctx, base_dir)
                    use_tools = (_supports_tool_loop(p)
                                 and _model_has_tools(p, base_dir))
                    used = _estimate_context_tokens(p, base_dir, history,
                                                    mcp, use_tools)
                    over = (" [yellow](session override)[/yellow]"
                            if ctx.get("max_context") else "")
                    if not maxc:
                        console.print(
                            f"  context used: [bold]~{used:,}[/bold] tokens  "
                            "[dim](model max unknown — set it with "
                            "/setcontext <n>)[/dim]")
                    else:
                        pct = min(100, round(used * 100 / maxc)) if maxc else 0
                        filled = min(20, round(pct / 5))
                        bar = "█" * filled + "░" * (20 - filled)
                        col = "green" if pct < 75 else "yellow" if pct < 90 else "red"
                        console.print(
                            f"  context  [bold]~{used:,}[/bold] / {maxc:,} tokens"
                            f"  [dim]({pct}%)[/dim]{over}")
                        console.print(f"  [{col}]{bar}[/{col}]  "
                                      "[dim]estimate (~4 chars/token)[/dim]")
            elif cmd == "/setcontext":
                arg = text[len("/setcontext"):].strip()
                if not arg:
                    maxc = _effective_max_context(ctx, base_dir)
                    cur = f"{maxc:,}" if maxc else "unknown"
                    console.print(f"  [dim]current max context:[/dim] "
                                  f"[bold]{cur}[/bold]  [dim]usage: /setcontext "
                                  "<number>  (e.g. 32000 or 32k)[/dim]")
                else:
                    n = _parse_ctx_number(arg)
                    if not n:
                        console.print("  [yellow]invalid number.[/yellow] "
                                      "[dim]e.g. /setcontext 32000 or "
                                      "/setcontext 128k[/dim]")
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

        # Plain message → query the attached model (needs one selected first).
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

        # Accumulate streamed text (and an interrupted flag) at this scope so the
        # post-turn guard can close the turn coherently even on Ctrl-C.
        streamed_text: list = []
        interrupted = False

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
                                               mcp, _on_tool, _on_text)
                if streamed_text:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                if reply:
                    # Already streamed to screen — just keep it for context.
                    history.append({"role": "assistant", "content": reply})
            else:
                reply = query_model(ctx["profile"], base_dir, history)
                if reply:
                    history.append({"role": "assistant", "content": reply})
        except (KeyboardInterrupt, SystemExit):
            # psai's streamers sys.exit(130) on Ctrl-C mid-reply; stay in the REPL.
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
