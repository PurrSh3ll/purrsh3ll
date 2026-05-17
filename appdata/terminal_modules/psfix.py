#!/usr/bin/env python3
"""
psfix.py — AI-powered terminal error explainer/fixer for PurrSh3ll.
Reads the last command entry from terminal_history.jsonl and sends it to AI.
"""

import json
import os
import sys


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


def _clean_command(text: str) -> str:
    """Extract a single shell command from AI response, stripping markdown/explanations."""
    lines = []
    in_fence = False
    for raw in text.strip().splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or stripped:
            lines.append(stripped)

    for line in lines:
        # Skip obvious prose lines
        if line.lower().startswith(("the ", "here ", "you ", "try ", "this ", "use ", "note")):
            continue
        # Strip surrounding backticks
        if line.startswith("`") and line.endswith("`"):
            line = line[1:-1]
        if line:
            return line

    # Fallback: first non-empty line
    for line in text.strip().splitlines():
        if line.strip():
            return line.strip()
    return text.strip()


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psfix", add_help=False)
    parser.add_argument("--explain",    action="store_true",
                        help="Explain why the command failed instead of suggesting a fix")
    parser.add_argument("--paste-mode", action="store_true",
                        help="Stream to stderr, print only clean command to stdout (used by zsh wrapper)")
    parser.add_argument("--base-dir",   default=None, metavar="DIR")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psfix — AI-powered terminal error explainer/fixer\n\n"
            "Usage:\n"
            "  psfix             Paste the corrected command at the prompt\n"
            "  psfix --explain   Explain why the last command failed\n\n"
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

    if args.explain:
        prompt = f"Command: {cmd}\nExit code: {exit_code}\n"
        if output:
            prompt += f"Output:\n{output}\n"
        prompt += (
            "\nExplain concisely why this command failed and what the error means. "
            "Be direct and practical."
        )
        _ai._info(f"Explaining: {cmd}\n")
        messages = [{"role": "user", "content": prompt}]
        _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)

    else:
        # Fix mode: ask for ONLY the corrected command
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
            # Stream visible on stderr, capture stdout for zsh print -z
            real_stdout = sys.stdout
            sys.stdout  = sys.stderr
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
            finally:
                sys.stdout = real_stdout
            if response:
                print(_clean_command(response))
        else:
            _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)


if __name__ == "__main__":
    main()
