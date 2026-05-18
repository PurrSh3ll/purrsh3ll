#!/usr/bin/env python3
"""
pscmd.py — AI-powered shell command generator for PurrSh3ll.
Accepts a natural-language description and returns the shell command to run.
"""

import os
import platform
import sys


def _clean_command(text: str) -> str:
    """Extract the shell command from AI response.
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

    parser = argparse.ArgumentParser(prog="pscmd", add_help=False)
    parser.add_argument("description", nargs="*", help="Natural-language description of the command to generate")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR",
                        help="Current working directory (for context)")
    parser.add_argument("-m", "--model", default=None, metavar="MODEL",
                        help="Override model from active profile")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.description:
        print(
            "pscmd — AI-powered shell command generator\n\n"
            "Usage:\n"
            "  pscmd <description>            Generate a shell command from description\n"
            "  pscmd -m <model> <description> Use a specific model\n\n"
            "Examples:\n"
            "  pscmd list all open ports\n"
            "  pscmd find files modified in the last 24 hours\n"
            "  pscmd kill process using port 8080\n"
            "  pscmd -m gpt-4o list all open ports\n"
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

    api_key          = _ai._load_api_key(profile.get("name", ""), base_dir)
    provider         = profile.get("provider", "ollama")
    url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
    model            = args.model or profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

    description = " ".join(args.description)
    cwd = (args.cwd or "").strip()
    sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    prompt = f"System: {sys_info}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    prompt += (
        f"\nGenerate a shell command that: {description}\n\n"
        "Return ONLY the shell command — no explanation, no markdown, no backticks, "
        "just the raw command on a single line."
    )

    _ai._info(f"Generating: {description}\n")
    messages = [{"role": "user", "content": prompt}]

    # Stream to stderr (visible via 2>/dev/tty), print clean command to stdout
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
