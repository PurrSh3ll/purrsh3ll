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
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.description:
        print(
            "pscmd — AI-powered shell command generator\n\n"
            "Usage:\n"
            "  pscmd <description>              Generate a shell command from description\n"
            "  pscmd -p <profile> <description> Use a specific saved profile\n\n"
            "Examples:\n"
            "  pscmd list all open ports\n"
            "  pscmd find files modified in the last 24 hours\n"
            "  pscmd kill process using port 8080\n"
            "  pscmd -p openai-gpt4o list all open ports\n"
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

    api_key          = _ai._load_api_key(profile.get("name", ""), base_dir)
    provider         = profile.get("provider", "ollama")
    url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
    model            = profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking", False))
    temperature      = _ai._profile_temperature(profile)
    use_tools        = _ai._tools_enabled(profile, base_dir)

    _CMD_TOOL = {
        "name":        "run_command",
        "description": "Return the single shell command that accomplishes the requested task",
        "parameters": {
            "type":       "object",
            "properties": {
                "command": {
                    "type":        "string",
                    "description": "The shell command, ready to execute as-is",
                }
            },
            "required": ["command"],
        },
    }

    description = " ".join(args.description)
    cwd = (args.cwd or "").strip()
    sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    prompt = f"System: {sys_info}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    prompt += f"\nGenerate a shell command that: {description}\n"
    if use_tools:
        prompt += "\nCall run_command with the shell command."
    else:
        prompt += (
            "\nReturn ONLY the shell command — no explanation, no markdown, no backticks, "
            "just the raw command on a single line."
        )

    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info(f"Generating: {description}\n")
    messages = [{"role": "user", "content": prompt}]

    def _run_text() -> str | None:
        # Stream to stderr (visible via 2>/dev/tty), keep stdout for the command
        _real_stdout = sys.stdout
        sys.stdout   = sys.stderr
        try:
            return _ai._run_llm(provider, model, messages, url, api_key,
                                disable_thinking, custom_params, hide_thinking, temperature)
        finally:
            sys.stdout = _real_stdout

    if use_tools:
        cmd = _ai._run_llm_tool_call(provider, model, messages, _CMD_TOOL, url, api_key)
        if cmd:
            # The tool-call path does not stream, so echo the command to stderr
            # (visible via 2>/dev/tty) so the user sees it before the paste
            # prompt — mirroring how the text path streams to the terminal.
            sys.stderr.write(cmd + "\n")
            sys.stderr.flush()
            print(cmd)
        else:
            # Fallback to text path if the tool call fails
            response = _run_text()
            if response:
                cmd = _clean_command(response)
                if cmd:
                    print(cmd)
    else:
        response = _run_text()
        if response:
            cmd = _clean_command(response)
            if cmd:
                print(cmd)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
