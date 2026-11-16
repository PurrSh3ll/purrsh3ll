"""purragent_core.dbview — extracted from monolithic purragent.py (Phase A refactor)."""

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style
from rich.console import Group
from rich.text import Text
import os
import psai
import purragent_db
import shutil
import sys

from purragent_core._shared import (AGENT_OUTPUT_RESERVE_TOK, AGENT_TEMPERATURE, FILL_FRAC, PURRAGENT_SYSTEM, VIOLET, console)
from purragent_core.models import (_effective_max_context, _env_block)
from purragent_core.providers import (_chat_stream, _openai_endpoint)
from purragent_core.ui import (_alt_screen, _box_table_frags, _drain_stdin, _render_ansi, _stream_view, show_view)

def _target_db_context(base_dir: str, max_chars=None) -> str:
    """Everything the engagement database knows about the current target, as plain text.
    The priority block (objective, target, ports, credentials) is always kept; the
    potentially long/numerous endpoints and notes are added only while they fit
    `max_chars`, so this can't grow past its share of the model's window."""
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
    # Lower-priority, unbounded-in-count section: fit to the remaining budget. Findings
    # (incl. the privesc-enum dumps) come first so the exploit agent can act on them.
    extra = [f"finding [{f.get('port') or 'host'}] {f.get('service') or ''}: {f['finding']}"
             for f in eng.get("exploit_findings", [])
             if f.get("finding") and f.get("service") != "report"]
    extra += [f"endpoint: {e.get('url')}" for e in eng.get("endpoints", [])]
    extra += [f"note: {n['text']}" for n in eng.get("notes", [])
              if n.get("kind") != "raw-intake" and n.get("text")]
    if max_chars is None:
        lines += extra
    else:
        used = len("\n".join(lines))
        omitted = 0
        for x in extra:
            if used + len(x) + 1 > max_chars:
                omitted += 1
                continue
            lines.append(x)
            used += len(x) + 1
        if omitted:
            lines.append(f"note: (+{omitted} more endpoint(s)/note(s) omitted to fit "
                         "the window)")
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
    # Fit the findings dump to the window (this is a single tool-free call: system +
    # dbctx + the question). None window → uncapped, as before.
    _bmax = _effective_max_context(ctx, base_dir)
    dbctx = _target_db_context(
        base_dir, max(0, int(_bmax * 4 * FILL_FRAC) - len(PURRAGENT_SYSTEM)
                      - AGENT_OUTPUT_RESERVE_TOK * 4) if _bmax else None)
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

