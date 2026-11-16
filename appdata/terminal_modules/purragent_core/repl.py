"""purragent_core.repl — extracted from monolithic purragent.py (Phase A refactor)."""

from prompt_toolkit import PromptSession
from prompt_toolkit.application import get_app
from prompt_toolkit.completion import Completer
from prompt_toolkit.completion import Completion
from prompt_toolkit.filters import completion_is_selected
from prompt_toolkit.filters import has_completions
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style
from rich.text import Text
import argparse
import atexit
import conv_memory
import json
import mcp_client
import os
import psai
import purragent_db
import shutil
import signal
import sys
import threading
import time

from purragent_core._shared import (AGENT_MODES, BLINK_CYCLE, BLINK_LEN, BLINK_REFRESH, DEFAULT_GREETING, DEFAULT_MODE, HACK_SLASH, SLASH, SLASH_SUBCOMMANDS, SQUINT_CYCLE, SQUINT_LEN, VIOLET, _MCP_NAME_SUBS, _NO_MODEL, console)
from purragent_core.agent import (_maybe_recall, _maybe_summarize, _remember_exchange)
from purragent_core.graph.integration import run_agent_graph
from purragent_core.chrome import (_banner_panel, _confirm_action, _context_view, _memory_view, pick_model)
from purragent_core.dbview import (_btw_chat, _db_view)
from purragent_core.hack import (_brute_running, _cancel_engagement, _flush_pending, _record_target, _run_hack, _start_hacking, _status_view)
from purragent_core.mcp import (_doctor_view, _mcp_add, _mcp_view, elevate)
from purragent_core.models import (_effective_max_context, _estimate_context_tokens, _find_profile, _fmt_ctx, _is_root, _model_capability, _model_has_tools, _model_short, _parse_ctx_number, _profiles, _supports_tool_loop)
from purragent_core.providers import (query_model)
from purragent_core.state import (_clear_findings, _clear_memories, _delete_memory_index, _load_state, _save_state)
from purragent_core.tools import (_tool_arg_preview, _tool_status)
from purragent_core.ui import (_ToolSpinner, _cli_help_epilog, _erase_prompt_line, _logo_text, _pause_after_command, _render_ansi, pick_mode, print_help)


class PromptHistory(InMemoryHistory):
    """In-session history that omits slash commands: pressing ↑ walks back through
    the messages you sent the model, not /model, /help, /greeting, etc."""

    def append_string(self, string: str) -> None:
        if string.lstrip().startswith("/"):
            return
        super().append_string(string)



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



def _wipe_session_stores(base_dir: str, ctx: dict) -> None:
    """Erase every store a session remembers: the engagement DB (targets/credentials),
    the user memories (/memory) and recorded findings (save_finding) kept in the state
    file, and the conversation-recall index. Config in the state file (attached profile,
    mode, greeting) is left intact. Run at BOTH session start and exit so nothing lingers
    on disk between runs — not even in the window after the agent is closed."""
    purragent_db.reset(base_dir)
    _clear_memories(base_dir)
    _clear_findings(base_dir)
    try:
        ctx["conv_mem"].reset()
    except Exception:                                  # noqa: BLE001
        pass



def run_repl(base_dir: str, config: dict, profile: dict | None) -> None:
    ctx = {"profile": profile, "max_context": None,   # max_context: session override
           "session_id": str(int(time.time())),       # tags this session's recalled turns
           "conv_mem": conv_memory.ConversationMemory(base_dir)}   # created once (no race)
    # A new session starts with a clean slate — nothing carries over. Wipe every
    # remembered store: the engagement DB (targets/credentials from a previous or
    # crashed run), the user memories (/memory) and recorded findings (save_finding)
    # kept in the state file, and the conversation-recall index. Config (attached
    # profile, mode, greeting) lives in the same state file but is left intact.
    _wipe_session_stores(base_dir, ctx)

    # Guarantee the exit wipe also runs when the console window is closed (SIGHUP) or the
    # process is killed (SIGTERM) — not only on a graceful /exit or Ctrl-D. The final wipe
    # below is plain code after the loop, so a signal would otherwise skip it and leave
    # memories/findings/conv-recall on disk until the next launch. atexit doesn't fire on
    # those signals, so we also install explicit handlers that wipe then re-raise the
    # signal with the default disposition. A once-guard keeps it to a single wipe no matter
    # which path fires. (SIGINT is deliberately left alone: Ctrl-C at the prompt just
    # clears the line and must not quit.)
    _wiped = {"done": False}

    def _wipe_once() -> None:
        if _wiped["done"]:
            return
        _wiped["done"] = True
        _wipe_session_stores(base_dir, ctx)

    def _sig_wipe(signum, _frame):
        _wipe_once()
        try:                                   # restore default and re-raise for a clean exit
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        except Exception:                      # noqa: BLE001 — last resort
            os._exit(0)

    atexit.register(_wipe_once)
    for _signame in ("SIGTERM", "SIGHUP"):
        _sig = getattr(signal, _signame, None)
        if _sig is not None:
            try:
                signal.signal(_sig, _sig_wipe)
            except (ValueError, OSError):      # not main thread / unsupported — skip
                pass

    history: list = []
    remember_thread = None    # last background conv-recall indexer; joined before exit wipe
    _state = _load_state(base_dir)
    greeting = _state.get("greeting") or DEFAULT_GREETING
    mode = _state.get("mode") or DEFAULT_MODE   # skeleton: inert
    debug = False   # /debug: mirror pschat's --debug (dump the request to the model)
    hack_mode = False   # /hack: hacking mode on → shows in the toolbar; /hack again disables
    hack_goal = None    # /hack: chosen objective shortcode (flag/privesc/vuln/access)
    # semi-auto/confirm 'always allow' memory: exact calls approved with 'a' this
    # session (in-RAM only, never persisted; cleared by /clear).
    approvals: set = set()

    def _confirm(name, args, reason):
        return _confirm_action(name, args, reason, approvals)

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
            # /target, /start, /stop, /status are offered only while hacking mode is on.
            extra_provider=lambda: (list(HACK_SLASH) if hack_mode else [])),
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
                approvals.clear()                      # forget 'always allow' choices
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
                    # Changing the mode resets the trust posture: drop any 'always
                    # allow' choices so a switch to a stricter mode really re-asks.
                    forgot = len(approvals)
                    approvals.clear()
                    hint = next((h for n, h in AGENT_MODES if n == mode), "")
                    console.print(f"  [green]▸[/green] agent mode: "
                                  f"[bold]{mode}[/bold] [dim]— {hint}[/dim]")
                    if forgot:
                        console.print(Text(f"      cleared {forgot} remembered "
                                           "approval(s)", style="bright_black"))
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
                if not hack_mode:
                    console.print("  [yellow]/target[/yellow] is only available in "
                                  "hacking mode [dim]— enable it with[/dim] "
                                  "[cyan]/hack[/cyan]")
                elif _db_view(base_dir):
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
                if not hack_mode:
                    console.print("  [yellow]/status[/yellow] is only available in "
                                  "hacking mode [dim]— enable it with[/dim] "
                                  "[cyan]/hack[/cyan]")
                else:
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
        recall_block = ""
        if use_tools:
            ensure_mcp()
            # Keep the verbatim history within its % budget: condense the oldest turns
            # that overflow into ctx['summary'] (dropping them from history).
            _maybe_summarize(ctx["profile"], base_dir, ctx, mcp, mode, history)
            # Fill the reserved memory-lookup slot: recall relevant past/other-session
            # turns for the current question.
            recall_block = _maybe_recall(ctx, base_dir, history)

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
        # "Warming up" spinner shown between hitting Enter and the first output — covers
        # the one-time tool-retriever build (embedding model load) + the request's
        # time-to-first-token, so the first prompt never looks frozen.
        warmup = {"obj": None}
        # Set by the tool loop if the model calls enable_hacking_mode(enable=true);
        # a mutable holder because a closure can't rebind run_repl's locals.
        hack_signal = {"requested": False}

        def _on_hack():
            hack_signal["requested"] = True

        def _stop_tool_spin():
            if tool_spin["obj"] is not None:
                tool_spin["obj"].stop()
                tool_spin["obj"] = None

        def _stop_warmup():
            if warmup["obj"] is not None:
                warmup["obj"].stop()
                warmup["obj"] = None

        def _on_text(piece):
            _stop_warmup()             # first content byte — backstop for on_first_token
            streamed_text.append(piece)
            sys.stdout.write(piece)
            sys.stdout.flush()

        try:
            if use_tools and mcp.has_tools():
                def _on_tool(kind, name, payload):
                    _stop_warmup()     # first tool activity — backstop for on_first_token
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
                warmup["obj"] = _ToolSpinner("working").start()   # until first output
                reply = run_agent_graph(ctx["profile"], base_dir, history,
                                               mcp, _on_tool, _on_text,
                                               mode=mode, on_confirm=_confirm,
                                               offer_hack=not hack_mode,
                                               on_hack=_on_hack,
                                               summary=ctx.get("summary", ""),
                                               recall=recall_block,
                                               max_context=_effective_max_context(
                                                   ctx, base_dir),
                                               on_first_token=_stop_warmup)
                _stop_warmup()             # defensive: never leave the warmup spinner on
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
                        warmup["obj"] = _ToolSpinner("working").start()
                        reply = run_agent_graph(
                            ctx["profile"], base_dir, history, mcp, _on_tool,
                            _on_text, mode=mode, on_confirm=_confirm,
                            offer_hack=False, summary=ctx.get("summary", ""),
                            recall=recall_block,
                            max_context=_effective_max_context(ctx, base_dir),
                            on_first_token=_stop_warmup)
                        _stop_warmup()
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
            _stop_warmup()             # clear the warmup spinner if we broke early
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

        # Index the just-completed exchange for future recall (normal chat only, in the
        # background so the embed + disk write never blocks the next prompt).
        if (not hack_mode and len(history) >= 2
                and history[-1].get("role") == "assistant"
                and history[-2].get("role") == "user"):
            remember_thread = threading.Thread(
                target=_remember_exchange,
                args=(ctx, base_dir, history[-2].get("content"),
                      history[-1].get("content")), daemon=True)
            remember_thread.start()

    mcp.close()   # shut down any MCP server subprocesses we spawned
    # Wipe everything the session remembered so nothing lingers on disk after the agent
    # is closed (not just at the next start). Join a still-running recall indexer first,
    # otherwise its background write could re-create the conv-memory files after the wipe.
    if remember_thread is not None and remember_thread.is_alive():
        remember_thread.join(timeout=5)
    _wipe_once()
    console.print("  [dim]bye[/dim]")



def main() -> None:
    parser = argparse.ArgumentParser(
        prog="purragent",
        description=(
            "purragent — interactive console AI agent for PurrSh3ll.\n"
            "\n"
            "A tool-using agent that plans and works right in the terminal. It runs in\n"
            "two modes: a general-purpose assistant for everyday and pentest/HTB tasks,\n"
            "and an autonomous hacking mode (/hack). Tools are discovered on demand via\n"
            "RAG, so you can connect unlimited MCP servers without bloating the prompt.\n"
            "Works with local and cloud models (OpenAI-compatible and native Anthropic)."
        ),
        epilog=_cli_help_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--base-dir", default=None, metavar="DIR",
        help="PurrSh3ll root directory (auto-detected; the launcher sets this — "
             "you normally don't need it)")
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

