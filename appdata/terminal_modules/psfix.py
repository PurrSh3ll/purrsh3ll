#!/usr/bin/env python3
"""
psfix.py — AI-powered terminal error explainer/fixer for PurrSh3ll.
Reads the last command entry from terminal_history.jsonl and sends it to AI.
"""

import json
import os
import platform
import sys

_ANALYZE_HISTORY_TOKENS = 6_000  # token budget for terminal history in analyze mode


def _last_terminal_entry(base_dir: str) -> dict | None:
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            return json.loads(lines[-1])
    except Exception:
        pass
    return None


def _load_recent_history(base_dir: str, token_budget: int, _ai) -> str:
    """Load recent terminal history as formatted string, limited by token budget.
    Returns entries in chronological order (oldest → newest)."""
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception:
        return ""

    entries = []
    for l in lines:
        try:
            entries.append(json.loads(l))
        except Exception:
            pass

    # Walk newest → oldest, accumulate within budget, then reverse for display
    collected = []
    used = 0
    for entry in reversed(entries):
        ec  = entry.get("exit_code", 0)
        cmd = entry.get("cmd", "")
        out = entry.get("output", "")[:400]  # cap per-entry output to keep things concise
        status = f"exit {ec}" if ec != 0 else "ok"
        part = f"$ {cmd} [{status}]"
        if out:
            part += f"\n{out}"
        tokens = _ai._count_tokens(part)
        if used + tokens > token_budget:
            break
        collected.append(part)
        used += tokens

    if not collected:
        return ""
    return "\n".join(reversed(collected))


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
    parser.add_argument("--explain",    action="store_true",
                        help="Explain why the command failed")
    parser.add_argument("--analyze",    action="store_true",
                        help="Deep analysis using terminal history and working directory")
    parser.add_argument("--paste-mode", action="store_true",
                        help="Suppress streaming; print only clean command to stdout (used internally)")
    parser.add_argument("--base-dir",   default=None, metavar="DIR")
    parser.add_argument("--cwd",        default=None, metavar="DIR",
                        help="Working directory where the command was run")
    # Direct data args (passed by the Fix overlay button, bypasses history file)
    parser.add_argument("--cmd",        default=None, metavar="CMD")
    parser.add_argument("--exit-code",  default=None, type=int, metavar="N")
    parser.add_argument("--output",     default=None, metavar="OUTPUT")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psfix — AI-powered terminal error explainer/fixer\n\n"
            "Usage:\n"
            "  psfix             Paste the corrected command at the prompt\n"
            "  psfix --explain   Explain why the last command failed\n"
            "  psfix --analyze   Deep analysis with terminal history and cwd context\n\n"
            "psfix reads the last entry from terminal history automatically.\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    # Reuse AI machinery from psai (same directory)
    sys.path.insert(0, os.path.dirname(__file__))
    import psai as _ai

    config  = _ai._load_config(base_dir)
    profile = _ai._active_profile(config)
    if not profile:
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

    # ── Analyze mode ──────────────────────────────────────────────────────────
    if args.analyze:
        cwd = (args.cwd or "").strip()
        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        history_text = _load_recent_history(base_dir, _ANALYZE_HISTORY_TOKENS, _ai)

        prompt = f"System: {sys_info}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        prompt += f"\nFailed command: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        if history_text:
            prompt += f"\nRecent terminal session history:\n{history_text}\n"
        prompt += (
            "\nBased on the system info, working directory, and terminal history, "
            "provide a deep analysis of why this command failed. "
            "Consider the full context — previous commands, environment, permissions — "
            "and suggest the most accurate fix. Be specific and practical.\n"
            "At the very end, on a new line, write ONLY the corrected command "
            "with no prefix, no explanation, no backticks — just the raw command."
        )
        _ai._info(f"Analyzing: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        # Stream analysis to stderr (visible in terminal via 2>/dev/tty),
        # then print only the fix command to stdout (captured by zsh $())
        import io as _io
        _real_stdout = sys.stdout
        sys.stdout   = sys.stderr
        try:
            response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
        finally:
            sys.stdout = _real_stdout

        if response:
            fix = _clean_command(response)
            if fix:
                print(fix)

    # ── Explain mode ──────────────────────────────────────────────────────────
    elif args.explain:
        prompt = f"Command: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        prompt += (
            "\nExplain concisely why this command failed and what the error means. "
            "Be direct and practical.\n"
            "At the very end, on a new line, write ONLY the corrected command "
            "with no prefix, no explanation, no backticks — just the raw command."
        )
        _ai._info(f"Explaining: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        # Stream explanation to stderr (visible via 2>/dev/tty),
        # then print only the fix command to stdout (captured by zsh $())
        _real_stdout = sys.stdout
        sys.stdout   = sys.stderr
        try:
            response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
        finally:
            sys.stdout = _real_stdout

        if response:
            fix = _clean_command(response)
            if fix:
                print(fix)

    # ── Fix mode ──────────────────────────────────────────────────────────────
    else:
        prompt = f"Command: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        prompt += (
            "\nReturn ONLY the corrected shell command. "
            "No explanation, no markdown, no backticks — just the raw command on a single line."
        )
        _ai._info(f"Fixing: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]

        if args.paste_mode:
            import io
            _buf = io.StringIO()
            _real_stdout = sys.stdout
            sys.stdout = _buf
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
            finally:
                sys.stdout = _real_stdout
            if response:
                print(_clean_command(response))
        else:
            _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)


if __name__ == "__main__":
    main()
