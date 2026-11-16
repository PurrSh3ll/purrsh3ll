"""purragent_core.ui — extracted from monolithic purragent.py (Phase A refactor)."""

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.console import Group
from rich.table import Table
from rich.text import Text
import contextlib
import io
import os
import shutil
import sys
import threading

from purragent_core._shared import (AGENT_MODES, DEFAULT_MODE, FALLBACK_PAW, HACK_SLASH, LOGO_PATHS, SLASH, VIOLET, _THINK_SPINNER)

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



def _logo_text(variant: str = "open") -> Text:
    """The logo silhouette (open / blink / squint eyes), painted violet."""
    path = LOGO_PATHS.get(variant, LOGO_PATHS["open"])
    try:
        with open(path, encoding="utf-8") as f:
            art = f.read().rstrip("\n")
    except Exception:
        art = FALLBACK_PAW
    return Text(art, style=VIOLET)



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



def _toggle_notice(status: str, info: str) -> str:
    """A short result line for an enable/disable action inside the /mcp view."""
    return {
        "enabled":  "  ✓ enabled" + (f" · {info}" if info else ""),
        "disabled": "  ✓ disabled",
        "builtin":  "  built-in — can't change",
        "error":    f"  ✗ {info[:44]}",
        "missing":  "  ✗ no such server",
    }.get(status, "")



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
    hack_grid = Table.grid(padding=(0, 2))
    hack_grid.add_column(style=f"bold {VIOLET}", no_wrap=True)
    hack_grid.add_column(style="dim")
    for cmd, hint in HACK_SLASH:
        hack_grid.add_row(cmd, hint)
    return _render_ansi(Group(
        Text("purragent — commands", style="bold white"),
        Text(""),
        grid,
        Text(""),
        Text.from_markup("hacking mode only [dim]— enable with[/dim] "
                         "[bold]/hack[/bold]", style="bold white"),
        Text(""),
        hack_grid,
        Text(""),
        Text.from_markup(
            "Type a message and press [bold]Enter[/bold] to ask the attached model.\n"
            "[bold]Ctrl-C[/bold] interrupts a reply · [bold]Ctrl-D[/bold] quits."),
    ))



def print_help() -> None:
    show_view(_help_body())



def _skeleton_body(title: str, note: str) -> str:
    """A placeholder overlay for commands that aren't implemented yet."""
    return _render_ansi(Group(
        Text(title, style=f"bold {VIOLET}"),
        Text(""),
        Text(note, style="dim"),
        Text(""),
        Text("Not implemented yet — coming soon.", style="yellow"),
    ))



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



def _render_plan(steps: list) -> str:
    """One-line-per-step checklist of the model's current update_plan, injected each
    round so it stays in view (weak models otherwise lose the thread mid-task)."""
    mark = {"done": "x", "doing": "»", "todo": " "}
    lines = []
    for i, s in enumerate(steps, 1):
        st = str((s or {}).get("status") or "todo").strip().lower()
        txt = str((s or {}).get("text") or "").strip()
        lines.append(f"[{mark.get(st, ' ')}] {i}. {txt}")
    return ("CURRENT PLAN (your update_plan — keep working through it, call update_plan "
            "to change a status):\n" + "\n".join(lines))



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



def _cli_help_epilog() -> str:
    """Build the `--help` epilog from the same command/mode tables the REPL uses,
    so CLI help never drifts from what the app actually offers."""
    out = ["run modes (switch inside with /mode):"]
    out += [f"  {name:<11} {hint}" for name, hint in AGENT_MODES]
    out += ["", "commands (type these once purragent is running):"]
    out += [f"  {cmd:<12} {hint}" for cmd, hint in SLASH]
    out += ["", "hacking-mode commands (available after /hack):"]
    out += [f"  {cmd:<12} {hint}" for cmd, hint in HACK_SLASH]
    out += ["",
            "first run: type /model to attach a model, then just start typing.",
            "everything the agent remembers is wiped when the session ends."]
    return "\n".join(out)

