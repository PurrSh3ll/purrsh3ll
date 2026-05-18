#!/usr/bin/env python3
"""
psview.py — AI-powered screenshot / image analyzer for PurrSh3ll.
Sends an image to the active vision-capable AI profile, streams analysis,
and saves a synthetic entry to terminal_history.jsonl so psnext / psreport
can incorporate the findings.

Optional --next flag: after analysis runs a psnext-style prompt and asks
whether to paste the best suggested command at the zsh prompt.
"""

import base64
import json
import os
import platform
import sys
import time

_SUPPORTED_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
_MEDIA_TYPES   = {
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif":  "image/gif",
}
_DEFAULT_QUESTION = (
    "You are an expert penetration tester. Analyze this screenshot carefully. "
    "Identify and extract all security-relevant information visible: "
    "IP addresses, hostnames, open ports, services and versions, "
    "vulnerabilities, error messages, credentials, hashes, URLs, "
    "tool output, and any other findings. "
    "Be specific — extract exact values, not just descriptions."
)
_HISTORY_TOKENS = 6_000   # budget for psnext inline analysis


def _read_image(path: str) -> tuple[str, str]:
    """Read image file, return (base64_data, media_type). Raises on error."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in _SUPPORTED_EXT:
        raise ValueError(f"Unsupported format '{ext}'. Supported: {', '.join(_SUPPORTED_EXT)}")
    with open(path, "rb") as f:
        data = f.read()
    return base64.b64encode(data).decode("ascii"), _MEDIA_TYPES[ext]


def _build_messages(b64: str, media_type: str, question: str, provider: str) -> list:
    """Build multimodal messages list for the given provider."""
    if provider == "anthropic":
        return [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
            {"type": "text", "text": question},
        ]}]
    # OpenAI-compatible: ollama, openai, groq, gemini, openrouter, huggingface
    return [{"role": "user", "content": [
        {"type": "text", "text": question},
        {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}},
    ]}]


def _save_to_history(base_dir: str, filename: str, analysis: str, cwd: str):
    """Append a synthetic psscreenshot entry to terminal_history.jsonl."""
    entry = {
        "cmd":       f"[psscreenshot: {filename}]",
        "output":    analysis[:800],
        "exit_code": 0,
        "ts":        int(time.time()),
        "cwd":       cwd,
    }
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        pass  # history write failure is non-fatal


def _load_history_for_next(base_dir: str, token_budget: int, _ai) -> tuple[str, int]:
    """Load recent terminal history (including the just-saved screenshot entry)."""
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
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


def _clean_command(text: str) -> str:
    """Extract last meaningful shell command from AI response."""
    lines_raw = text.strip().splitlines()
    filtered  = []
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


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psview", add_help=False)
    parser.add_argument("image",    nargs="?",  default=None,
                        help="Path to image file (PNG, JPG, JPEG, WebP, GIF)")
    parser.add_argument("question", nargs="*",
                        help="Optional question about the image")
    parser.add_argument("--next",     action="store_true",
                        help="After analysis, run psnext-style next-step suggestion (uses full history)")
    parser.add_argument("--cmd",      action="store_true",
                        help="After analysis, ask y/n to paste the best command (image only, no history)")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-m", "--model", default=None, metavar="MODEL",
                        help="Override model from active profile")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.image:
        print(
            "psview — AI-powered screenshot / image analyzer\n\n"
            "Usage:\n"
            "  psview <image>                      Analyze image with default pentest prompt\n"
            "  psview <image> \"<question>\"         Ask a specific question about the image\n"
            "  psview <image> --cmd                Analyze and paste best command (image only)\n"
            "  psview <image> --next               Analyze and suggest next steps (full history)\n"
            "  psview -m <model> <image>           Use a specific model\n\n"
            "Supported formats: PNG, JPG, JPEG, WebP, GIF\n\n"
            "Requires a vision-capable model (Claude, GPT-4o, llava, moondream, etc.).\n"
            "The analysis is saved to terminal history so psnext/psreport can use it.\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    cwd = (args.cwd or "").strip()

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
    ctx_tokens       = int(profile.get("context_tokens") or 0) or _ai._default_ctx(provider)

    # ── Load image ─────────────────────────────────────────────────────────────
    image_path = args.image
    if not os.path.isfile(image_path):
        _ai._err(f"File not found: {image_path}")
        sys.exit(1)

    try:
        b64, media_type = _read_image(image_path)
    except ValueError as e:
        _ai._err(str(e))
        sys.exit(1)
    except Exception as e:
        _ai._err(f"Cannot read image: {e}")
        sys.exit(1)

    filename = os.path.basename(image_path)
    question = " ".join(args.question).strip() if args.question else ""
    if not question:
        question = _DEFAULT_QUESTION

    # For --cmd: append instruction to write the command on the last line
    cmd_question = question
    if args.cmd:
        cmd_question = (
            question + "\n\n"
            "At the very end, on a new line, write ONLY the single most important command "
            "to run based solely on what you see in this image — "
            "no prefix, no explanation, no backticks, just the raw command."
        )

    messages = _build_messages(b64, media_type, cmd_question, provider)

    # ── Stream analysis ────────────────────────────────────────────────────────
    _ai._info(f"Analyzing {filename} with {model}...\n")

    stream_to_stderr = args.next or args.cmd
    if stream_to_stderr:
        # Stream to stderr (visible via 2>/dev/tty), capture response for further processing
        _real_stdout = sys.stdout
        sys.stdout   = sys.stderr
        try:
            analysis = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
        finally:
            sys.stdout = _real_stdout
    else:
        analysis = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)

    if not analysis:
        _ai._err("No response from model.")
        sys.exit(1)

    # ── Save synthetic history entry ───────────────────────────────────────────
    _save_to_history(base_dir, filename, analysis, cwd)
    _ai._info(f"\nSaved to terminal history as [psscreenshot: {filename}]\n")

    # ── --cmd: paste best command based on image only ──────────────────────────
    if args.cmd:
        cmd = _clean_command(analysis)
        if cmd:
            print(cmd)
        sys.exit(0)

    if not args.next:
        sys.exit(0)

    # ── --next: psnext-style analysis using updated history ────────────────────
    history_budget = ctx_tokens // 2
    history, count = _load_history_for_next(base_dir, history_budget, _ai)
    if not history:
        sys.exit(0)

    sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    prompt   = f"System: {sys_info}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    prompt += f"\nRecent terminal session ({count} commands, including screenshot analysis):\n{history}\n"
    prompt += (
        "\nYou are an expert penetration tester. Based on the terminal history above "
        "(including the screenshot analysis):\n"
        "1. Briefly summarize what has been discovered or accomplished so far.\n"
        "2. Identify gaps — what has NOT been checked yet that could be relevant.\n"
        "3. Suggest 3-5 concrete next steps with the exact commands to run, ordered by priority.\n"
        "Be specific, practical, and focused on the attack surface visible in the history.\n"
        "At the very end, on a new line, write ONLY the single most important command to run next "
        "— no prefix, no explanation, no backticks, just the raw command."
    )

    _ai._info("Analyzing next steps...\n")
    next_messages = [{"role": "user", "content": prompt}]

    _real_stdout = sys.stdout
    sys.stdout   = sys.stderr
    try:
        next_response = _ai._run_llm(provider, model, next_messages, url, api_key, disable_thinking, custom_params)
    finally:
        sys.stdout = _real_stdout

    if next_response:
        cmd = _clean_command(next_response)
        if cmd:
            print(cmd)


if __name__ == "__main__":
    main()
