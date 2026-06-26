#!/usr/bin/env python3
"""
psfix.py — AI-powered terminal error explainer/fixer for PurrSh3ll.
Reads the last command entry from terminal_history.db and sends it to AI.
"""

import os
import platform
import sqlite3
import sys


def _db_connect(base_dir: str) -> sqlite3.Connection | None:
    path = (os.environ.get("PSDB")
            or os.path.join(base_dir, "appdata", "logs", "terminal_history.db"))
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _last_terminal_entry(base_dir: str) -> dict | None:
    conn = _db_connect(base_dir)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT cmd, exit_code, output FROM commands ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        if row:
            return {"cmd": row["cmd"], "exit_code": row["exit_code"], "output": row["output"] or ""}
    except Exception:
        pass
    finally:
        conn.close()
    return None


def _load_recent_history(base_dir: str, limit: int = 40, broad_limit: int = 0,
                         recent_output_cap: int = 400) -> str:
    """Load terminal history as formatted string (oldest → newest).

    limit             — recent entries sent with output (capped at recent_output_cap chars)
    broad_limit       — older entries sent with cmd + exit code only (no output);
                        fetched as OFFSET limit, so they never overlap with recent
    recent_output_cap — max chars of output per recent entry (default 400)
    """
    conn = _db_connect(base_dir)
    if conn is None:
        return ""
    try:
        recent_rows = conn.execute(
            "SELECT cmd, exit_code, output FROM commands ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        broad_rows = []
        if broad_limit > 0:
            broad_rows = conn.execute(
                "SELECT cmd, exit_code FROM commands ORDER BY ts DESC LIMIT ? OFFSET ?",
                (broad_limit, limit),
            ).fetchall()
    except Exception:
        return ""
    finally:
        conn.close()

    parts = []

    # Extended history (oldest context, commands only)
    if broad_rows:
        parts.append("Extended history (commands only):")
        for row in reversed(broad_rows):
            ec     = row["exit_code"] if row["exit_code"] is not None else 0
            cmd    = row["cmd"] or ""
            status = f"exit {ec}" if ec != 0 else "ok"
            parts.append(f"$ {cmd} [{status}]")
        parts.append("")  # blank separator

    # Recent history (with output)
    if recent_rows:
        parts.append("Recent history (with output):")
        for row in reversed(recent_rows):
            ec     = row["exit_code"] if row["exit_code"] is not None else 0
            cmd    = row["cmd"] or ""
            out    = (row["output"] or "")[:recent_output_cap]
            status = f"exit {ec}" if ec != 0 else "ok"
            part   = f"$ {cmd} [{status}]"
            if out:
                part += f"\n{out}"
            parts.append(part)

    return "\n".join(parts)


def _trim_output_head_tail(output: str, max_chars: int) -> str:
    """Trim output to max_chars using head (60%) + tail (40%) with omission marker."""
    if len(output) <= max_chars:
        return output
    head = int(max_chars * 0.60)
    tail = max_chars - head
    omitted = len(output) - head - tail
    return output[:head] + f"\n[... {omitted:,} chars omitted ...]\n" + output[-tail:]


def _clean_command(text: str) -> str:
    """Extract the corrected shell command from AI response.
    Takes the LAST meaningful line to handle <think> blocks and preamble."""
    lines_raw = text.strip().splitlines()

    # Strip markdown code fences and <think>/<thinking> blocks
    filtered = []
    in_fence = False
    in_think = False
    for raw in lines_raw:
        s = raw.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            continue
        lo = s.lower()
        if "<think>" in lo or "<thinking>" in lo:
            in_think = True
        if in_think:
            if "</think>" in lo or "</thinking>" in lo:
                in_think = False
            continue
        if not in_fence and not s:
            continue
        filtered.append(s)

    # Remove obvious prose lines, strip backticks
    candidates = []
    for line in filtered:
        if line.lower().startswith(("the ", "here ", "you ", "try ", "this ", "use ", "note", "#")):
            continue
        if line.startswith("`") and line.endswith("`"):
            line = line[1:-1]
        if line:
            candidates.append(line)

    # Return LAST candidate — command follows thinking/explanation
    if candidates:
        return candidates[-1]

    # Fallback: last non-empty raw line
    for line in reversed(lines_raw):
        if line.strip():
            return line.strip()
    return text.strip()


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psfix", add_help=False)
    parser.add_argument("-e", "--explain", action="store_true",
                        help="Explain why the command failed")
    parser.add_argument("-a", "--analyze", action="store_true",
                        help="Deep analysis using terminal history and working directory")
    parser.add_argument("--fit", action="store_true",
                        help="Used with -a: auto-fit history to model context window (fill-down: "
                             "50%% failed output / 30%% recent / remaining broad)")
    parser.add_argument("--paste-mode", action="store_true",
                        help="Suppress streaming; print only clean command to stdout (used internally)")
    parser.add_argument("--base-dir",   default=None, metavar="DIR")
    parser.add_argument("--cwd",        default=None, metavar="DIR",
                        help="Working directory where the command was run")
    # Direct data args (passed by the Fix overlay button, bypasses history file)
    parser.add_argument("--cmd",        default=None, metavar="CMD")
    parser.add_argument("--exit-code",  default=None, type=int, metavar="N")
    parser.add_argument("--output",     default=None, metavar="OUTPUT")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psfix — AI-powered terminal error explainer/fixer\n\n"
            "Usage:\n"
            "  psfix                      Paste the corrected command at the prompt\n"
            "  psfix -e, --explain        Explain why the last command failed\n"
            "  psfix -a, --analyze        Deep analysis with terminal history and cwd context\n"
            "  psfix --fit                Auto-fit output to model ctx window (head+tail trim)\n"
            "  psfix -a --fit             Analyze: auto-fit output + history (fill-down)\n"
            "  psfix -p, --profile        Use a specific saved profile\n\n"
            "psfix reads the last entry from terminal_history.db automatically.\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    # Reuse AI machinery from psai (same directory)
    sys.path.insert(0, os.path.dirname(__file__))
    import psai as _ai

    if args.debug:
        _ai._DEBUG_PROMPT = True

    config  = _ai._load_config(base_dir)
    profile = _ai._resolve_profile(config, args.profile)
    if not profile:
        if not args.profile:
            _ai._err("No active API profile. Set one in AI Settings > API Providers.")
        sys.exit(1)

    api_key = _ai._load_api_key(profile.get("name", ""), base_dir)

    # Data can come from direct args (overlay button) or from history file (manual psfix)
    if args.cmd is not None and args.exit_code is not None:
        cmd       = args.cmd
        exit_code = args.exit_code
        output    = (args.output or "").strip()
    else:
        entry = _last_terminal_entry(base_dir)
        if not entry:
            _ai._err("No terminal history found — run a command first.")
            sys.exit(1)
        cmd       = entry.get("cmd", "")
        exit_code = entry.get("exit_code", 0)
        output    = entry.get("output", "").strip()

    if exit_code == 0:
        _ai._info("Last command exited successfully (exit 0) — nothing to fix.")
        sys.exit(0)

    provider         = profile.get("provider", "ollama")
    url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
    model            = profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking", False))
    use_tools        = _ai._tools_enabled(profile, base_dir)

    # Tool definition reused across all modes
    _FIX_TOOL = {
        "name":        "fix_command",
        "description": "Return the single corrected shell command that fixes the error",
        "parameters": {
            "type":       "object",
            "properties": {
                "command": {
                    "type":        "string",
                    "description": "The corrected shell command, ready to execute as-is",
                }
            },
            "required": ["command"],
        },
    }

    # ── Analyze mode ──────────────────────────────────────────────────────────
    if args.analyze:
        cwd = (args.cwd or "").strip()
        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        if args.fit:
            # Fill-down: allocate 75% of ctx_window across 3 areas by priority.
            # Fixed overhead (system info + cmd header + instructions): ~200 tokens.
            # Area 1 — failed cmd output : up to 50% of data budget
            # Area 2 — recent with output: up to 30% of data budget
            # Area 3 — broad cmd only    : remaining (fill-down from Areas 1+2 surplus)
            ctx_window  = _ai._get_ctx_window(profile, base_dir)
            if ctx_window:
                data_budget   = int(ctx_window * 0.75) - 200   # tokens available for data
                area1_budget  = int(data_budget * 0.50)        # tokens for failed output
                area2_budget  = int(data_budget * 0.30)        # tokens for recent history
                # Trim failed cmd output to Area 1 budget
                output        = output[:area1_budget * 4]
                area1_actual  = len(output) // 4               # tokens actually used
                # Per-entry output cap for recent history
                recent_limit      = _ai._TERMINAL_HIST_LIMIT
                recent_output_cap = max(50, (area2_budget * 4) // max(1, recent_limit))
                # Area 3 gets everything left after Areas 1+2 (fill-down surplus included)
                area3_budget  = data_budget - area1_actual - area2_budget
                broad_limit   = max(0, area3_budget // 15)     # ~15 tokens per broad entry
                sys.stderr.write(
                    f"  [--fit] ctx={ctx_window//1000}K  "
                    f"output≤{area1_budget}t  "
                    f"recent≤{area2_budget}t ({recent_output_cap}c/entry)  "
                    f"broad≤{broad_limit} cmds\n"
                )
                sys.stderr.flush()
            else:
                # ctx_window unknown — fall back to defaults
                recent_limit      = _ai._TERMINAL_HIST_LIMIT
                recent_output_cap = 400
                broad_limit       = _ai._TERMINAL_HIST_BROAD_LIMIT
                sys.stderr.write("  [--fit] ctx unknown — using defaults\n")
                sys.stderr.flush()

            history_text = _load_recent_history(
                base_dir,
                limit=recent_limit,
                broad_limit=broad_limit,
                recent_output_cap=recent_output_cap,
            )
        else:
            history_text = _load_recent_history(
                base_dir,
                limit=_ai._TERMINAL_HIST_LIMIT,
                broad_limit=_ai._TERMINAL_HIST_BROAD_LIMIT,
            )

        prompt = f"System: {sys_info}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        prompt += f"\nFailed command: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        if history_text:
            prompt += f"\nRecent terminal session history:\n{history_text}\n"
        if use_tools:
            prompt += (
                "\nBased on the system info, working directory, and terminal history, "
                "provide a deep analysis of why this command failed. "
                "Consider the full context — previous commands, environment, permissions — "
                "and suggest the most accurate fix. Be specific and practical. "
                "Then call fix_command with the corrected command."
            )
        else:
            prompt += (
                "\nBased on the system info, working directory, and terminal history, "
                "provide a deep analysis of why this command failed. "
                "Consider the full context — previous commands, environment, permissions — "
                "and suggest the most accurate fix. Be specific and practical.\n"
                "At the very end, on a new line, write ONLY the corrected command "
                "with no prefix, no explanation, no backticks — just the raw command."
            )
        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info(f"Analyzing: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        if use_tools:
            fix = _ai._run_llm_tool_call(provider, model, messages, _FIX_TOOL, url, api_key)
            if fix:
                print(fix)
        else:
            # Stream analysis to stderr (visible in terminal via 2>/dev/tty),
            # then print only the fix command to stdout (captured by zsh $())
            import io as _io
            _real_stdout = sys.stdout
            sys.stdout   = sys.stderr
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
            finally:
                sys.stdout = _real_stdout

            if response:
                fix = _clean_command(response)
                if fix:
                    print(fix)

    # ── Explain mode ──────────────────────────────────────────────────────────
    elif args.explain:
        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        prompt = f"System: {sys_info}\nCommand: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        if use_tools:
            prompt += (
                "\nExplain concisely why this command failed and what the error means. "
                "Be direct and practical. "
                "Then call fix_command with the corrected command."
            )
        else:
            prompt += (
                "\nExplain concisely why this command failed and what the error means. "
                "Be direct and practical.\n"
                "At the very end, on a new line, write ONLY the corrected command "
                "with no prefix, no explanation, no backticks — just the raw command."
            )
        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info(f"Explaining: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        if use_tools:
            fix = _ai._run_llm_tool_call(provider, model, messages, _FIX_TOOL, url, api_key)
            if fix:
                print(fix)
        else:
            # Stream explanation to stderr (visible via 2>/dev/tty),
            # then print only the fix command to stdout (captured by zsh $())
            _real_stdout = sys.stdout
            sys.stdout   = sys.stderr
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
            finally:
                sys.stdout = _real_stdout

            if response:
                fix = _clean_command(response)
                if fix:
                    print(fix)

    # ── Fix mode ──────────────────────────────────────────────────────────────
    else:
        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        if args.fit and output:
            # Fit output to 75% ctx_window minus fixed overhead (~100 tokens).
            # Uses head (60%) + tail (40%) so model sees both the beginning
            # (banner, config) and the end (errors, final result) of large outputs.
            ctx_window = _ai._get_ctx_window(profile, base_dir)
            if ctx_window:
                output_budget_chars = max(200, (int(ctx_window * 0.75) - 100) * 4)
                output = _trim_output_head_tail(output, output_budget_chars)
                sys.stderr.write(
                    f"  [--fit] ctx={ctx_window // 1000}K  "
                    f"output≤{output_budget_chars:,} chars (head+tail)\n"
                )
                sys.stderr.flush()

        prompt = f"System: {sys_info}\nCommand: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        if use_tools:
            prompt += "\nCall fix_command with the corrected shell command."
        else:
            prompt += (
                "\nReturn ONLY the corrected shell command. "
                "No explanation, no markdown, no backticks — just the raw command on a single line."
            )
        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info(f"Fixing: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        if use_tools:
            fix = _ai._run_llm_tool_call(provider, model, messages, _FIX_TOOL, url, api_key)
            if fix:
                print(fix)
            else:
                # Fallback to text path if tool call fails
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
                if response:
                    print(_clean_command(response))
        elif args.paste_mode:
            import io
            _buf = io.StringIO()
            _real_stdout = sys.stdout
            sys.stdout = _buf
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
            finally:
                sys.stdout = _real_stdout
            if response:
                print(_clean_command(response))
        else:
            _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
