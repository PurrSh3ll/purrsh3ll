"""purragent_core.mcp — extracted from monolithic purragent.py (Phase A refactor)."""

from rich.console import Console
from rich.console import Group
from rich.table import Table
from rich.text import Text
import getpass
import io
import mcp_client
import os
import shutil
import sys
import time

from purragent_core._shared import (ENABLE_TIMEOUT, MCP_PROBE_TIMEOUT, VIOLET, _PKG_HINT, console)
from purragent_core.models import (_is_root)
from purragent_core.ui import (_alt_screen, _read_key, _render_ansi, _toggle_notice, show_view)

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

