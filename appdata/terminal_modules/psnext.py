#!/usr/bin/env python3
"""
psnext.py — AI-powered pentest next-step advisor for PurrSh3ll.
Reads terminal_history.jsonl and suggests the most promising next moves.
"""

import json
import os
import platform
import sys


def _clean_command(text: str) -> str:
    """Extract the last meaningful shell command from AI response.
    Handles <think> blocks, markdown fences, and prose lines."""
    lines_raw = text.strip().splitlines()

    filtered = []
    in_fence  = False
    in_think  = False
    for raw in lines_raw:
        s  = raw.strip()
        lo = s.lower()
        if s.startswith("```"):
            in_fence = not in_fence
            continue
        if "<think>" in lo or "<thinking>" in lo:
            in_think = True
        if in_think:
            if "</think>" in lo or "</thinking>" in lo:
                in_think = False
            continue
        if not in_fence and not s:
            continue
        filtered.append(s)

    candidates = []
    for line in filtered:
        if line.lower().startswith(("the ", "here ", "you ", "try ", "this ", "use ", "note", "#")):
            continue
        if line.startswith("`") and line.endswith("`"):
            line = line[1:-1]
        if line:
            candidates.append(line)

    if candidates:
        return candidates[-1]
    for line in reversed(lines_raw):
        if line.strip():
            return line.strip()
    return text.strip()

_HISTORY_TOKENS = 8_000  # token budget for terminal history context


def _load_history(base_dir: str, token_budget: int, _ai) -> tuple[str, int]:
    """Load terminal history within token budget (newest → oldest, then reversed).
    Returns (formatted_history, total_entries_loaded)."""
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return "", 0
    except Exception:
        return "", 0

    entries = []
    for l in lines:
        try:
            entries.append(json.loads(l))
        except Exception:
            pass

    collected = []
    used = 0
    for entry in reversed(entries):
        ec     = entry.get("exit_code", 0)
        cmd    = entry.get("cmd", "")
        out    = entry.get("output", "")[:600]
        cwd    = entry.get("cwd", "")
        status = f"exit {ec}" if ec != 0 else "ok"
        part   = f"$ {cmd} [{status}]"
        if cwd:
            part += f"  # cwd: {cwd}"
        if out:
            part += f"\n{out}"
        tokens = _ai._count_tokens(part)
        if used + tokens > token_budget:
            break
        collected.append(part)
        used += tokens

    if not collected:
        return "", 0
    return "\n".join(reversed(collected)), len(collected)


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psnext", add_help=False)
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("--target",   default=None, metavar="TARGET",
                        help="Target host/network for additional context")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psnext — AI pentest next-step advisor\n\n"
            "Usage:\n"
            "  psnext                       Suggest next steps based on terminal history\n"
            "  psnext --target 192.168.1.0/24  Include target context\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    sys.path.insert(0, os.path.dirname(__file__))
    import psai as _ai

    config  = _ai._load_config(base_dir)
    profile = _ai._active_profile(config)
    if not profile:
        _ai._err("No active API profile. Set one in AI Settings > API Providers.")
        sys.exit(1)

    api_key          = _ai._load_api_key(profile.get("name", ""), base_dir)
    provider         = profile.get("provider", "ollama")
    url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
    model            = profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

    history, count = _load_history(base_dir, _HISTORY_TOKENS, _ai)
    if not history:
        _ai._err("No terminal history found — run some commands first.")
        sys.exit(1)

    sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    cwd      = (args.cwd or "").strip()
    target   = (args.target or "").strip()

    prompt  = f"System: {sys_info}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    if target:
        prompt += f"Target: {target}\n"
    prompt += f"\nRecent terminal session ({count} commands):\n{history}\n"
    prompt += (
        "\nYou are an expert penetration tester. Based on the terminal history above:\n"
        "1. Briefly summarize what has been discovered or accomplished so far.\n"
        "2. Identify gaps — what has NOT been checked yet that could be relevant.\n"
        "3. Suggest 3-5 concrete next steps with the exact commands to run, ordered by priority.\n"
        "Be specific, practical, and focused on the attack surface visible in the history.\n"
        "At the very end, on a new line, write ONLY the single most important command to run next "
        "— no prefix, no explanation, no backticks, just the raw command."
    )

    _ai._info("Analyzing terminal history for next pentest steps...\n")
    messages = [{"role": "user", "content": prompt}]

    # Stream analysis to stderr (visible via 2>/dev/tty),
    # print the best command to stdout (captured by zsh $())
    _real_stdout = sys.stdout
    sys.stdout   = sys.stderr
    try:
        response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
    finally:
        sys.stdout = _real_stdout

    if response:
        cmd = _clean_command(response)
        if cmd:
            print(cmd)


if __name__ == "__main__":
    main()
