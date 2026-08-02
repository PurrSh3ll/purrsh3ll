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
import io
import json
import os
import sys
import time

# Reuse psai's provider/profile/LLM plumbing. psai lives in the same directory;
# importing it is side-effect-free (its main() is guarded by __main__).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psai  # noqa: E402

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
    ("/greeting", "set the welcome name (e.g. /greeting Neo)"),
    ("/help",     "show commands and usage"),
    ("/clear",    "clear the conversation"),
    ("/exit",     "quit purragent"),
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
    "and security research inside PurrSh3ll. Be concise and practical."
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


# ── Inline arrow-key selector (Claude-Code-style) ──────────────────────────────

def select_option(title: str, options: list, start: int = 0):
    """Render an inline list; navigate with ↑/↓, choose with Enter, cancel with Esc.

    options: list of (label, hint). Returns the chosen index, or None if cancelled.
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
        e.app.exit(result=idx[0])

    @kb.add("escape")
    @kb.add("c-c")
    def _(e):
        e.app.exit(result=None)

    def render():
        frags = [("class:title", f"  {title}\n")]
        for i, (label, hint) in enumerate(options):
            sel = i == idx[0]
            frags.append(("class:sel" if sel else "class:opt",
                          f"  {'❯' if sel else ' '} {label}"))
            if hint:
                frags.append(("class:hint", f"   {hint}"))
            frags.append(("", "\n"))
        frags.append(("class:footer", "  ↑/↓ move · enter select · esc cancel"))
        return frags

    control = FormattedTextControl(render, show_cursor=False)
    style = Style.from_dict({
        "title":  "bold",
        "sel":    "bold #d75fff",
        "opt":    "",
        "hint":   "#7f7f7f",
        "footer": "#7f7f7f italic",
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
        return app.run()


def pick_model(config: dict, current_name: str | None):
    """Show the profile picker.

    Returns the chosen profile dict, the _NO_MODEL sentinel (detach, for
    debugging), or None if the user cancelled.
    """
    profs = _profiles(config)
    if not profs:
        console.print(
            "  [yellow]No API profiles found.[/yellow] Add one in "
            "[bold]AI Settings ▸ API Providers[/bold] first.")
        return None
    # First entry detaches the model — handy for debugging the shell itself.
    options = [("No model", "detach — no LLM attached")]
    options += [(p.get("name", "?"),
                 f"{_model_short(p)} · {p.get('provider', '?')}") for p in profs]
    start = next((i + 1 for i, p in enumerate(profs)
                  if p.get("name") == current_name), 0)
    choice = select_option("Select a model", options, start=start)
    if choice is None:
        return None
    if choice == 0:
        return _NO_MODEL
    return profs[choice - 1]


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


def _banner_panel(profile: dict | None, logo: Text, greeting: str) -> Panel:
    left = Table.grid(padding=0)
    left.add_column()
    left.add_row(Text(f"Welcome back {greeting}!", style="bold white"))
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


def show_view(body: str, hint: str = "esc / q / enter to return") -> None:
    """Show content on the alternate screen buffer; any of Esc/q/Enter returns and
    the previous screen is restored, leaving no clutter in scrollback. Uses plain
    escapes + a raw key read (the standard pager approach — vim/less/htop)."""
    import termios
    import tty

    content = body.rstrip("\n") + f"\r\n\r\n\x1b[7m {hint} \x1b[0m"
    content = content.replace("\n", "\r\n")
    if not sys.stdin.isatty():
        return
    with _alt_screen():
        sys.stdout.write(content)
        sys.stdout.flush()
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\x1b", "q", "Q", "\r", "\n", " ", "\x03", ""):
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


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

    sys_parts = [PURRAGENT_SYSTEM]
    if custom_system:
        sys_parts.append(custom_system)
    msgs = [{"role": "system", "content": "\n\n".join(sys_parts)}] + history

    return psai._run_llm(provider, model, msgs, url, api_key,
                         disable_thinking, custom_params, hide_thinking, temperature)


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
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/") or " " in text:
            return
        for cmd, hint in SLASH:
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text),
                                 display=cmd, display_meta=hint)


# ── REPL ───────────────────────────────────────────────────────────────────────

def run_repl(base_dir: str, config: dict, profile: dict | None) -> None:
    ctx = {"profile": profile}
    history: list = []
    greeting = _load_state(base_dir).get("greeting") or DEFAULT_GREETING

    def toolbar():
        p = ctx["profile"]
        if not p:
            return HTML("  <style fg='#e5c07b'>no model</style> — type "
                        "<style fg='#61afef'>/model</style> to choose   "
                        "<style fg='#7f7f7f'>/exit to quit</style>")
        return HTML(
            f"  <b>{_model_short(p)}</b>  ·  {p.get('provider', '?')}"
            f"  ·  <i>{p.get('name', '?')}</i>   "
            f"<style fg='#7f7f7f'>/exit to quit</style>")

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
        completer=SlashCompleter(),
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
        if text.startswith("/") and " " not in text:
            if buf.complete_state is None:
                buf.start_completion(select_first=False)
        elif buf.complete_state is not None:
            buf.cancel_completion()

    session.default_buffer.on_text_changed += _autocomplete_slash

    # The welcome banner is shown as a live, blinking prompt message on the first
    # turn only; afterwards it scrolls away and the prompt is a plain "❯ ".
    hint = ("  \x1b[2mtype \x1b[36m/\x1b[0m\x1b[2m for commands · "
            "\x1b[36m/model\x1b[0m\x1b[2m to pick a model · a message to chat\x1b[0m\n")
    frames = {v: "\n" + _render_ansi(_banner_panel(profile, _logo_text(v), greeting)) + hint
              for v in ("open", "blink", "squint")}

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
    first = True

    while True:
        try:
            if first:
                text = session.prompt(banner_message,
                                      refresh_interval=BLINK_REFRESH).strip()
            else:
                text = session.prompt(plain_prompt).strip()
            first = False
        except KeyboardInterrupt:
            first = False     # Ctrl-C at the prompt: clear line, drop the banner
            continue
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
                history.clear()
                console.print("  [dim]conversation cleared[/dim]")
            elif cmd == "/model":
                cur = ctx["profile"].get("name") if ctx["profile"] else None
                chosen = pick_model(config, cur)
                if chosen is _NO_MODEL:
                    ctx["profile"] = None
                    _save_state(base_dir, profile=None)
                    console.print("  [yellow]○[/yellow] model detached "
                                  "[dim](no LLM attached)[/dim]")
                elif chosen:
                    ctx["profile"] = chosen
                    _save_state(base_dir, profile=chosen.get("name"))
                    console.print(
                        f"  [green]▸[/green] now using "
                        f"[bold]{_model_short(chosen)}[/bold] "
                        f"[dim]· {chosen.get('provider')}[/dim]")
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
                                  "[dim](shown next launch)[/dim]")
            else:
                console.print(f"  [yellow]unknown command:[/yellow] {cmd}  "
                              "[dim](/help for the list)[/dim]")
            continue

        # Plain message → query the attached model (needs one selected first).
        if not ctx["profile"]:
            console.print("  [yellow]No model selected.[/yellow] Type "
                          "[cyan]/model[/cyan] to choose one first.")
            continue

        history.append({"role": "user", "content": text})
        try:
            reply = query_model(ctx["profile"], base_dir, history)
            if reply:
                history.append({"role": "assistant", "content": reply})
        except (KeyboardInterrupt, SystemExit):
            # psai's streamers sys.exit(130) on Ctrl-C mid-reply; stay in the REPL.
            console.print("\n  [dim]interrupted[/dim]")

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
