"""purragent_core.hack — extracted from monolithic purragent.py (Phase A refactor)."""

from rich.console import Console
from rich.text import Text
import io
import ipaddress
import json
import mcp_client
import os
import psai
import purragent_db
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from purragent_core._shared import (AGENT_DBCTX_FRAC, AGENT_OUTPUT_RESERVE_TOK, AGENT_TEMPERATURE, AGENT_TURN_MAX_SECONDS, BRUTE_MAX_PARALLEL, BRUTE_MINUTES, BRUTE_THREADS, CRED_VALIDATE_MAX, CURL_MAX_TIME_SECONDS, DERIVE_BUDGET_MINUTES, DERIVE_VALIDATE_MAX, EXPLOIT_AGENT_BUDGET_MINUTES, EXPLOIT_AGENT_MAX_ROUNDS, EXPLOIT_AGENT_MAX_TOOLCALLS, EXPLOIT_CMD_MINUTES, EXTRACT_TURN_MAX_SECONDS, FILL_FRAC, FLAG_HUNT_BUDGET_MINUTES, FLAG_HUNT_MAX, PORT_SCAN_MINUTES, PRIVESC_ENUM_BUDGET_MINUTES, PRIVESC_ENUM_MAX, PURRAGENT_SYSTEM, REVIEW_BUDGET_MINUTES, REVIEW_MAX_ROUNDS, REVIEW_MAX_TOOLCALLS, SERVICE_REVIEW_BUDGET_MINUTES, SERVICE_REVIEW_MAX_ROUNDS, SERVICE_REVIEW_MAX_TOOLCALLS, VIOLET, _AGENT_SECRET_ARGS, _BRUTE_FALLBACK_PASSWORDS, _BRUTE_PASS_FILES, _BRUTE_SEED_USERS, _BRUTE_SERVICES, _CPE_ALIAS, _CRED_EXTRACT_SYSTEM, _CRED_VALIDATE_TIMEOUT, _CVE_STORE_CAP, _DEFAULT_CREDS, _DERIVE_SUFFIXES, _EXPLOIT_AGENT_SYSTEM, _EXPLOIT_AGENT_TASK, _EXPLOIT_AGENT_TOOLS, _EXPLOIT_DENY_BINS, _EXPLOIT_EXTRACT_SYSTEM, _EXPLOIT_FILL_OK, _FLAG_HUNT_TIMEOUT, _FLAG_RE, _HACK_ANNOUNCEMENT, _HACK_GOAL, _HACK_TRANSLATE_INSTRUCTIONS, _HASH32_LINE, _HYDRA_HIT, _LOOT_SERVICES, _NIX_LOOT, _NULL_ANON_CREDS, _PORT_PASS_LABEL, _PRIVESC_ENUM_TIMEOUT, _PRIVESC_FINDING_CAP, _PRIVESC_SERVICES, _RECORD_SYS, _RECORD_TARGET_TOOL, _REPORT_SYSTEM, _REVIEW_SYSTEM, _REVIEW_TASK, _REVIEW_TOOLS, _SERVICE_REVIEW_SYSTEM, _STATE_TAG, _STATUS_STATE, _VULN_AUTH_TITLE, _VULN_PORT_FALLBACK, _VULN_SCRIPTS, _VULN_SSL, _VULN_TLS_PORTS, _WIN_LOOT, _msgs_budget_chars, _trim_agent_msgs, console)
from purragent_core.dbview import (_host_label, _target_db_context)
from purragent_core.models import (_effective_max_context, _env_block, _is_root, _supports_tool_loop)
from purragent_core.providers import (_chat_stream, _openai_endpoint)
from purragent_core.tools import (_get_retriever, _tool_available)
from purragent_core.ui import (_alt_screen, _drain_stdin, _read_key)

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
    """/hack — enable hacking mode. Confirm, then print a static English announcement
    (no LLM — small models are unreliable at this) and ask for the target IP as step 1.
    The objective is always "capture the flag". Returns (announcement, goal_shortcode)
    if enabled — the caller waits for the IP next; (None, None) if declined/no model."""
    console.print(Text("      runs autonomously — an automated recon → exploitation "
                       "loop that won't stop to ask (independent of /mode)",
                       style="bright_black"))
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

    # Objective is always "capture the flag" — no prompt (hacking mode is a flag hunt).
    code = _HACK_GOAL
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



def _pass_label(label: str) -> str:
    return _PORT_PASS_LABEL.get(label, f"{label} port discovery")



def _next_seq(eng: dict) -> int:
    """Next engagement-wide command number, so [running N]/[complete N] increase
    monotonically across ALL phases (each command keeps the N it was announced with)."""
    with eng["lock"]:
        eng["seq"] = eng.get("seq", 0) + 1
        return eng["seq"]



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
    # dbctx rides in the untrimmable system slot, so bound it to a share of the window.
    _dbmax = _effective_max_context(ctx, base_dir)
    dbctx = _target_db_context(
        base_dir, int(_dbmax * 4 * AGENT_DBCTX_FRAC) if _dbmax else None) or ""
    system = "\n\n".join(p for p in (system_prompt, _env_block(), dbctx) if p)
    msgs = [{"role": "system", "content": system},
            {"role": "user", "content": task}]
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    custom_params = psai._parse_custom_params(profile)
    deadline = time.time() + budget_min * 60
    calls = 0
    trim_noted = False       # note the first context trim once per agent run
    seen: dict = {}          # (tool, canonical args) -> prior result text, for dedup
    if intro:
        _post(ctx, lambda: console.print(Text("  ▸ " + intro, style="bright_black")))

    for _round in range(max_rounds):
        if eng.get("cancelled") or time.time() > deadline:
            break
        # Keep the growing transcript within the window (tool outputs pile up with no
        # summariser here). Trim oldest groups first; tell the operator once.
        if _trim_agent_msgs(
                msgs, _msgs_budget_chars(_effective_max_context(ctx, base_dir), schemas)) \
                and not trim_noted:
            trim_noted = True
            _post(ctx, lambda: console.print(Text(
                "  ▸ trimmed older tool output to fit the context window",
                style="bright_black")))
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
    (budget[0]) runs out. Returns (tested, hit_key, hit_port, hit_tool)."""
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
            return tested, None, None, None
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
            return tested, key, port, tool
    return tested, None, None, None



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
        tested, hit_key, hit_port, hit_tool = _attempt_login(mcp, host, present, c, budget)
        if hit_key:
            purragent_db.set_cred_validated(base, c["id"], True, hit_port, tool=hit_tool)
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



def _loot_command(cred: dict, host: str, port: int, key: str):
    """(tool, args) that runs the read-only loot sweep over this service's login tool,
    reusing the validation arg-builders (which already handle key/password/hash), or
    None when the credential can't drive a shell here."""
    if key == "ssh":
        built, loot = _v_ssh(cred, host, port), _NIX_LOOT
    elif key == "winrm":
        built, loot = _v_winrm(cred, host, port), _WIN_LOOT
    else:
        return None
    if not built:
        return None
    tool, args = built
    args = dict(args)
    args["command"] = loot
    return tool, args



def _extract_flags(text: str) -> list:
    """Flag-looking strings in command output: flag{…}/HTB{…} literals plus bare 32-hex
    tokens on their own line (HTB user.txt/root.txt). Order-preserving, deduped."""
    out = list(_FLAG_RE.findall(text or ""))
    for line in (text or "").splitlines():
        s = line.strip()
        if _HASH32_LINE.match(s):
            out.append(s)
    seen: set = set()
    return [x for x in out if not (x in seen or seen.add(x))]



def _print_flag_hit(key: str, flag: str) -> None:
    line = Text("  ")
    line.append("[flag]", style="bold green")
    line.append(f" ▸ loot · {key}  ", style="green")
    line.append(flag, style="bold yellow")
    console.print(line)



def _run_flag_hunt(eng: dict) -> None:
    """Phase-5 flag hunt: with a validated shell login, sweep the usual flag/secret
    locations for a capture. Bounded and cancel-aware; a clean no-op when the host has
    no shell-capable service or no validated credential."""
    ctx = eng["ctx"]
    mcp = ctx.get("mcp")
    if mcp is None or eng.get("cancelled"):
        return
    base, tid, host = eng["base_dir"], eng["tid"], eng["ip"]
    present = _present_services(base, tid)
    targets = {k: present[k] for k in present if k in _LOOT_SERVICES}
    if not targets:
        return
    creds = [c for c in purragent_db.fetch_credentials(base, tid)
             if c.get("validated") == 1]
    if not creds:
        return
    _post(ctx, lambda: console.print(Text(
        "  ▸ flag hunt — search the usual paths with a validated login",
        style="bright_black")))
    budget = [FLAG_HUNT_MAX]
    deadline = time.time() + FLAG_HUNT_BUDGET_MINUTES * 60
    seen_flags: set = set()
    for c in creds:
        if seen_flags or eng.get("cancelled") or budget[0] <= 0 or time.time() > deadline:
            break
        hint = c.get("service_hint") or "*"
        keys = list(targets) if hint == "*" else ([hint] if hint in targets else [])
        for key in keys:
            if eng.get("cancelled") or budget[0] <= 0 or time.time() > deadline:
                break
            built = _loot_command(c, host, targets[key][0], key)
            if not built:
                continue
            tool, args = built
            budget[0] -= 1
            name = mcp_client._namespaced("hacktools", tool)
            try:
                res = mcp.call(name, args, timeout=_FLAG_HUNT_TIMEOUT)
            except Exception:                              # noqa: BLE001
                continue
            port = targets[key][0]
            for flag in _extract_flags(res.get("text") or ""):
                if flag in seen_flags:
                    continue
                seen_flags.add(flag)
                finding = f"flag captured via {key} ({_cred_display(c)}): {flag}"
                purragent_db.add_exploit_finding(base, tid, port, "tcp", key,
                                                 "flag-hunt", "", finding)
                eng.setdefault("exploit_findings", []).append(
                    {"port": port, "finding": finding})
                _post(ctx, lambda k=key, fl=flag: _print_flag_hit(k, fl))
            if seen_flags:
                break
    if not seen_flags and not eng.get("cancelled"):
        _post(ctx, lambda: console.print(Text(
            "    no flag found in the usual locations", style="bright_black")))



def _privesc_call(cred: dict, host: str, port: int, key: str):
    """(tool, args) for the platform privesc-enum MCP tool with this credential, or None
    when the credential can't drive a shell (mirrors _v_ssh / _v_winrm)."""
    if not cred.get("username"):
        return None
    if key == "ssh":
        args = {"host": host, "port": port, "username": cred["username"]}
        if cred.get("secret_type") == "ssh_key" and cred["secret"]:
            args["key"] = cred["secret"]
        elif cred["secret"]:
            args["password"] = cred["secret"]
        else:
            return None
        return "linux_privesc_enum", args
    if key == "winrm":
        args = {"host": host, "username": cred["username"]}
        if cred.get("secret_type") == "ntlm_hash" and cred["secret"]:
            args["hash"] = cred["secret"]
        elif cred["secret"]:
            args["password"] = cred["secret"]
        else:
            return None
        return "windows_privesc_enum", args
    return None



def _print_privesc_line(key: str, cred: dict) -> None:
    line = Text("  ")
    line.append("[privesc]", style="bold yellow")
    line.append(f" ▸ enum · {key}  {_cred_display(cred)}", style="yellow")
    console.print(line)



def _run_privesc_enum(eng: dict) -> None:
    """Phase-5 privesc enumeration: with a validated shell login, sweep the local-privesc
    vectors (sudo/SUID/caps/… via the hacktools privesc-enum tools) and store them as
    findings for the report and the exploit agent. Bounded, cancel-aware; a clean no-op
    without a shell login or a validated credential."""
    ctx = eng["ctx"]
    mcp = ctx.get("mcp")
    if mcp is None or eng.get("cancelled"):
        return
    base, tid, host = eng["base_dir"], eng["tid"], eng["ip"]
    present = _present_services(base, tid)
    targets = {k: present[k] for k in present if k in _PRIVESC_SERVICES}
    if not targets:
        return
    creds = [c for c in purragent_db.fetch_credentials(base, tid)
             if c.get("validated") == 1]
    if not creds:
        return
    _post(ctx, lambda: console.print(Text(
        "  ▸ privesc enum — gather local escalation vectors with a validated login",
        style="bright_black")))
    budget = [PRIVESC_ENUM_MAX]
    deadline = time.time() + PRIVESC_ENUM_BUDGET_MINUTES * 60
    done_pairs: set = set()          # (username, service) already swept
    ran = 0
    for c in creds:
        if eng.get("cancelled") or budget[0] <= 0 or time.time() > deadline:
            break
        hint = c.get("service_hint") or "*"
        keys = list(targets) if hint == "*" else ([hint] if hint in targets else [])
        for key in keys:
            if budget[0] <= 0 or eng.get("cancelled") or time.time() > deadline:
                break
            pair = (c.get("username") or "", key)
            if pair in done_pairs:
                continue
            built = _privesc_call(c, host, targets[key][0], key)
            if not built:
                continue
            tool, args = built
            budget[0] -= 1
            done_pairs.add(pair)
            name = mcp_client._namespaced("hacktools", tool)
            try:
                res = mcp.call(name, args, timeout=_PRIVESC_ENUM_TIMEOUT)
            except Exception:                              # noqa: BLE001
                continue
            text = (res.get("text") or "").strip()
            if not text or res.get("is_error") or res.get("isError"):
                continue
            port = targets[key][0]
            body = text[:_PRIVESC_FINDING_CAP] + (
                "\n[…truncated]" if len(text) > _PRIVESC_FINDING_CAP else "")
            finding = f"privesc vectors ({key}, {_cred_display(c)}):\n{body}"
            purragent_db.add_exploit_finding(base, tid, port, "tcp", "privesc",
                                             "privesc-enum", "", finding)
            eng.setdefault("exploit_findings", []).append(
                {"port": port, "finding": finding})
            ran += 1
            _post(ctx, lambda k=key, cc=c: _print_privesc_line(k, cc))
    if ran == 0 and not eng.get("cancelled"):
        _post(ctx, lambda: console.print(Text(
            "    no shell login available for privesc enumeration",
            style="bright_black")))



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
        _tested, hit_key, hit_port, hit_tool = _attempt_login(mcp, host, present, cand, budget)
        if hit_key:
            try:
                cid = purragent_db.add_credential(base, tid, cand["username"],
                    cand["secret"], "password", scope="specific",
                    service_hint=hit_key, source="derived")
                purragent_db.set_cred_validated(base, cid, True, hit_port, tool=hit_tool)
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
                purragent_db.set_cred_validated(base, cid, True, port, tool="hydra")
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
    _run_flag_hunt(eng)                                # loot common flag paths with valid logins
    _run_privesc_enum(eng)                             # gather local-privesc vectors (→ root flag)
    _run_exploit_agent(eng)                            # cross-service correlation + privesc (has creds)

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



def _report_context(base_dir: str, tid: int, max_chars=None) -> str:
    """A compact, deterministic dump of the findings (no commands) to summarise. The
    ports/vuln/CVE sections are small and always included; the enumeration findings
    (each up to the server's output cap) are added only while they fit `max_chars`, so
    a big engagement can't build a report prompt that overflows the model's window."""
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
        used = len("\n".join(lines))
        omitted = 0
        for e in ef:
            where = e["port"] if e.get("port") else "host"
            entry = [f"  [{where}] {ln.strip()}"
                     for ln in (e.get("finding") or "").splitlines() if ln.strip()]
            if not entry:
                continue
            chunk = len("\n".join(entry)) + 1
            if max_chars and used + chunk > max_chars:
                omitted += 1
                continue
            lines.extend(entry)
            used += chunk
        if omitted:
            lines.append(f"  … (+{omitted} more finding(s) omitted to fit the window)")
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
    # Fit the findings dump to the window: leave room for the system prompt and the
    # model's reply. None window → no cap (keeps prior behaviour).
    maxc = _effective_max_context(ctx, base)
    budget = (max(0, int(maxc * 4 * FILL_FRAC) - len(_REPORT_SYSTEM)
                  - AGENT_OUTPUT_RESERVE_TOK * 4) if maxc else None)
    context = _report_context(base, eng["tid"], budget)
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

