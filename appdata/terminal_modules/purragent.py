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
import json
import os
import re
import sys

# Reuse psai's provider/profile/LLM plumbing. psai lives in the same directory;
# importing it is side-effect-free (its main() is guarded by __main__).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psai  # noqa: E402

from prompt_toolkit import PromptSession                       # noqa: E402
from prompt_toolkit.application import Application             # noqa: E402
from prompt_toolkit.completion import Completer, Completion    # noqa: E402
from prompt_toolkit.formatted_text import HTML                 # noqa: E402
from prompt_toolkit.history import InMemoryHistory             # noqa: E402
from prompt_toolkit.key_binding import KeyBindings             # noqa: E402
from prompt_toolkit.layout import Layout, Window               # noqa: E402
from prompt_toolkit.layout.controls import FormattedTextControl  # noqa: E402
from prompt_toolkit.styles import Style                        # noqa: E402

from rich.console import Console                               # noqa: E402
from rich.panel import Panel                                   # noqa: E402
from rich.table import Table                                   # noqa: E402
from rich.text import Text                                     # noqa: E402
from rich import box                                           # noqa: E402

TOOL_NAME = "purragent"
WELCOME   = "Welcome back Hacker!"
VIOLET    = "#b46cff"     # single-colour fill for the paw logo + accents

# Brand mark: purragent's logo, pre-rendered to a small monochrome glyph
# silhouette (regenerate with `scripts/render_purragent_logo.py`).
# purragent paints it VIOLET at render time.
LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "purragent_logo.ans")
FALLBACK_PAW = "  _   _\n (_) (_)\n(_)   (_)\n  (___)"

# Slash commands offered in the / dropdown and listed by /help.
SLASH = [
    ("/model", "switch the attached model"),
    ("/help",  "show commands and usage"),
    ("/clear", "clear the conversation"),
    ("/exit",  "quit purragent"),
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


def _save_state(base_dir: str, state: dict) -> None:
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
        layout=Layout(Window(control)),
        key_bindings=kb,
        style=style,
        full_screen=False,
        mouse_support=False,
    )
    return app.run()


def pick_model(config: dict, current_name: str | None):
    """Show the profile picker. Returns the chosen profile dict, or None."""
    profs = _profiles(config)
    if not profs:
        console.print(
            "  [yellow]No API profiles found.[/yellow] Add one in "
            "[bold]AI Settings ▸ API Providers[/bold] first.")
        return None
    options = [(p.get("name", "?"),
                f"{_model_short(p)} · {p.get('provider', '?')}") for p in profs]
    start = next((i for i, p in enumerate(profs)
                  if p.get("name") == current_name), 0)
    choice = select_option("Select a model", options, start=start)
    if choice is None:
        return None
    return profs[choice]


# ── Banner + help ──────────────────────────────────────────────────────────────

def _app_version(base_dir: str) -> str:
    """Read PurrSh3ll's bundled __version__ from core/update_checker.py."""
    try:
        path = os.path.join(base_dir, "core", "update_checker.py")
        with open(path, encoding="utf-8") as f:
            m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', f.read())
        if m:
            return m.group(1)
    except Exception:
        pass
    return "1.3.0"


def _logo_text() -> Text:
    """The logo silhouette, painted a single violet colour."""
    try:
        with open(LOGO_PATH, encoding="utf-8") as f:
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


def print_banner(base_dir: str, profile: dict | None) -> None:
    version = _app_version(base_dir)

    left = Table.grid(padding=0)
    left.add_column()
    left.add_row(Text(WELCOME, style="bold white"))
    left.add_row("")
    left.add_row(_logo_text())
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

    console.print()
    console.print(Panel(
        body,
        title=f"[bold {VIOLET}]{TOOL_NAME}[/] [dim]v{version}[/]",
        title_align="left",
        border_style=VIOLET,
        padding=(1, 2),
        width=64,
    ))
    console.print("  [dim]type [cyan]/[/cyan] for commands · [cyan]/model[/cyan] "
                  "to pick a model · a message to chat[/dim]\n")


def print_help() -> None:
    console.print("\n  [bold]purragent commands[/bold]")
    for cmd, hint in SLASH:
        console.print(f"    [cyan]{cmd:<8}[/cyan] [dim]{hint}[/dim]")
    console.print(
        "\n  Type a message and press [bold]Enter[/bold] to ask the attached model.\n"
        "  Press [bold]Ctrl-C[/bold] to interrupt a reply, [bold]Ctrl-D[/bold] to quit.\n")


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
    session = PromptSession(
        history=InMemoryHistory(),
        completer=SlashCompleter(),
        complete_while_typing=True,
        bottom_toolbar=toolbar,
        style=style,
    )

    while True:
        try:
            text = session.prompt(HTML("<prompt>❯ </prompt>")).strip()
        except KeyboardInterrupt:
            continue          # Ctrl-C at the prompt: clear line, keep going
        except EOFError:
            break             # Ctrl-D: quit

        if not text:
            continue

        if text.startswith("/"):
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
                if chosen:
                    ctx["profile"] = chosen
                    _save_state(base_dir, {"profile": chosen.get("name")})
                    console.print(
                        f"  [green]▸[/green] now using "
                        f"[bold]{_model_short(chosen)}[/bold] "
                        f"[dim]· {chosen.get('provider')}[/dim]")
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

    print_banner(base_dir, profile)
    run_repl(base_dir, config, profile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.exit(130)
