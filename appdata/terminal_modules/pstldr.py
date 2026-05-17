#!/usr/bin/env python3
"""
pstldr.py — AI-powered TL;DR summarizer for PurrSh3ll.
Accepts text directly, a file path, or stdin via pipe.
"""

import os
import sys

_MAX_INPUT_CHARS = 120_000  # ~30k tokens — hard cap to avoid huge prompts


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="pstldr", add_help=False)
    parser.add_argument("input", nargs="*",
                        help="Text to summarize, or path to a file")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "pstldr — AI-powered TL;DR summarizer\n\n"
            "Usage:\n"
            "  pstldr <file>          Summarize a file\n"
            "  pstldr \"<text>\"        Summarize text passed directly\n"
            "  cat file | pstldr      Summarize piped input\n"
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

    # ── Resolve input ──────────────────────────────────────────────────────────
    source_label = "text"
    content = ""

    if not sys.stdin.isatty():
        # Piped input
        content = sys.stdin.read()
        source_label = "piped text"
    elif args.input:
        joined = " ".join(args.input)
        if os.path.isfile(joined):
            # Single file path
            try:
                with open(joined, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                source_label = f"file: {joined}"
            except Exception as e:
                _ai._err(f"Cannot read file: {e}")
                sys.exit(1)
        else:
            # Treat as literal text
            content = joined
            source_label = "text"
    else:
        _ai._err("No input provided. Pass text, a file path, or pipe content via stdin.")
        sys.exit(1)

    content = content.strip()
    if not content:
        _ai._err("Input is empty — nothing to summarize.")
        sys.exit(1)

    if len(content) > _MAX_INPUT_CHARS:
        _ai._info(f"Input truncated to {_MAX_INPUT_CHARS} characters.\n")
        content = content[:_MAX_INPUT_CHARS]

    # ── Build prompt ───────────────────────────────────────────────────────────
    prompt = (
        f"Summarize the following {source_label} concisely. "
        "Highlight the key points. Be clear and practical.\n\n"
        f"{content}"
    )

    _ai._info(f"Summarizing {source_label}...\n")
    messages = [{"role": "user", "content": prompt}]
    _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)


if __name__ == "__main__":
    main()
