#!/usr/bin/env python3
"""
pstldr.py — AI-powered TL;DR summarizer for PurrSh3ll.
Accepts text directly, a file path, or stdin via pipe.
"""

import os
import sys

_BINARY_CHECK_BYTES = 512


def _is_binary(path: str) -> bool:
    """Return True if the file appears to be binary (contains null bytes)."""
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(_BINARY_CHECK_BYTES)
    except Exception:
        return True


def _read_file(path: str) -> str | None:
    """Try to read a text file with common encodings."""
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="pstldr", add_help=False)
    parser.add_argument("input", nargs="*",
                        help="Text to summarize, or path to a file")
    parser.add_argument("--tail",     action="store_true",
                        help="Take the last part of the file instead of the first (useful for logs)")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("-m", "--model", default=None, metavar="MODEL",
                        help="Override model from active profile")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "pstldr — AI-powered TL;DR summarizer\n\n"
            "Usage:\n"
            "  pstldr <file>            Summarize a file (first part if truncated)\n"
            "  pstldr --tail <file>     Summarize a file (last part if truncated)\n"
            "  pstldr \"<text>\"          Summarize text passed directly\n"
            "  cat file | pstldr        Summarize piped input\n"
            "  pstldr -m <model> <file> Use a specific model\n"
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
    model            = args.model or profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

    # Derive max input size from profile context window (half for input, half for response)
    ctx_tokens     = int(profile.get("context_tokens") or 0) or _ai._default_ctx(provider)
    max_input_toks = ctx_tokens // 2
    max_chars      = max_input_toks * 4  # 1 token ≈ 4 chars

    # ── Resolve input ──────────────────────────────────────────────────────────
    source_label = "text"
    content = ""
    is_file = False

    if not sys.stdin.isatty():
        # Piped input
        content = sys.stdin.read()
        source_label = "piped text"
    elif args.input:
        joined = " ".join(args.input)
        if os.path.isfile(joined):
            if _is_binary(joined):
                _ai._err(f"File appears to be binary: {joined}\nOnly text files are supported.")
                sys.exit(1)
            content = _read_file(joined)
            if content is None:
                _ai._err(f"Cannot decode file (tried utf-8, utf-8-sig, latin-1): {joined}")
                sys.exit(1)
            source_label = f"file: {os.path.basename(joined)}"
            is_file = True
        else:
            content = joined
            source_label = "text"
    else:
        _ai._err("No input provided. Pass text, a file path, or pipe content via stdin.")
        sys.exit(1)

    content = content.strip()
    if not content:
        _ai._err("Input is empty — nothing to summarize.")
        sys.exit(1)

    # ── Truncate if needed ─────────────────────────────────────────────────────
    if len(content) > max_chars:
        if args.tail:
            content = content[-max_chars:]
            nl = content.find("\n")
            if 0 < nl < 200:
                content = content[nl + 1:]
            _ai._info(f"File truncated — summarizing last ~{max_input_toks // 1000}k tokens ({max_chars // 1000}k chars).\n")
        else:
            content = content[:max_chars]
            nl = content.rfind("\n")
            if nl > max_chars - 200:
                content = content[:nl]
            _ai._info(f"File truncated — summarizing first ~{max_input_toks // 1000}k tokens ({max_chars // 1000}k chars). Use --tail for the end.\n")

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
