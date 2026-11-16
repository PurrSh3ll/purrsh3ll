"""purragent_core.chrome — extracted from monolithic purragent.py (Phase A refactor)."""

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import mcp_client

from purragent_core._shared import (BANNER_COMMANDS, FILL_FRAC, FINDINGS_CAP_FRAC, FINDINGS_FLOOR_TOKENS, MEMORY_LOOKUP_TOKENS, ORANGE, OUTPUT_FLOOR, SUMMARIZED_CAP_FRAC, TOOL_NAME, VERSION, VIOLET, _NO_MODEL, _approval_key, console)
from purragent_core.models import (_effective_max_context, _fixed_header_parts, _fmt_ctx, _model_capability, _model_context, _model_has_tools, _model_short, _profiles)
from purragent_core.state import (_findings_block, _load_memories)
from purragent_core.tools import (_tool_arg_preview)
from purragent_core.ui import (_render_ansi, select_option, show_view)

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

    # FINDINGS: recorded findings (save_finding) are injected each turn — their real
    # size is the demand; the floor is still held and the cap bounds borrowing.
    findings_demand = len(_findings_block(base_dir))
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



def _confirm_action(name: str, args: dict, reason: str, approvals=None) -> bool:
    """Prompt the user to approve a tool call. Returns True to run it.

    `approvals` is an optional per-session set of keys the user chose to 'always
    allow'. If this exact call (tool + args) is in it, it runs silently; picking
    'a' at the prompt adds it so identical calls this session won't ask again."""
    key = _approval_key(name, args)
    tool = mcp_client.split_namespaced(name)[1]
    if approvals is not None and key in approvals:
        console.print(Text(f"  ✓ {tool} ", style="green")
                      .append("(approved earlier this session)", style="bright_black"))
        return True
    preview = _tool_arg_preview(args)
    line = Text("  ⚠ confirm  ", style="yellow")
    line.append(tool, style=f"bold {VIOLET}")
    if preview:
        line.append(f"  {preview}", style="bright_black")
    console.print(line)
    if reason:
        console.print(Text(f"      {reason}", style="bright_black"))
    prompt = ("      run this? [y/N/a] " if approvals is not None
              else "      run this? [y/N] ")
    try:
        ans = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans in ("a", "always") and approvals is not None:
        approvals.add(key)                             # remember this exact call
        console.print(Text("      won't ask again for this exact call this session",
                           style="bright_black"))
        return True
    if ans in ("y", "yes"):
        return True
    console.print(Text("      skipped", style="bright_black"))
    return False



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

