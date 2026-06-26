#!/usr/bin/env python3
"""
psview.py — AI-powered screenshot / image analyzer for PurrSh3ll.
Sends an image to the active vision-capable AI profile, streams analysis,
and saves a synthetic entry to terminal_history.db so psnext / psreport
can incorporate the findings.

The model is asked to append "Findings = true/false" at the end of its
response. The app parses this marker, tags the history entry accordingly
(tags: "screenshot" always, "findings" when true), and strips the marker
before saving the clean analysis text.
"""

import base64
import os
import re
import sqlite3
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
    "Be specific — extract exact values, not just descriptions.\n\n"
    "At the very end of your response, on a new line, write exactly one of:\n"
    "Findings = true   (if you identified any specific security-relevant data)\n"
    "Findings = false  (if nothing notable was found)"
)

# Matches: "Findings = true", "findings=True", "FINDINGS : yes", "findings=1", etc.
_FINDINGS_PATTERN = re.compile(
    r'^findings\s*[=:]\s*(true|yes|1)\s*$',
    re.IGNORECASE,
)
# Matches any findings marker line (true OR false) for stripping
_FINDINGS_ANY = re.compile(
    r'^findings\s*[=:]\s*(true|yes|1|false|no|0)\s*$',
    re.IGNORECASE,
)


def _parse_findings_marker(text: str) -> tuple[bool, str]:
    """
    Search the last 3 lines for a Findings marker.
    Returns (found: bool, cleaned_text: str) where cleaned_text has the
    marker line removed so it does not appear in saved output or terminal.
    """
    lines = text.rstrip().splitlines()
    tail  = lines[-3:] if len(lines) >= 3 else lines

    found = any(
        _FINDINGS_PATTERN.match(line.strip().rstrip('.,;: '))
        for line in tail
    )
    # Strip the marker line(s) from output
    clean = [l for l in lines if not _FINDINGS_ANY.match(l.strip().rstrip('.,;: '))]
    return found, '\n'.join(clean).rstrip()


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


def _db_connect(base_dir: str) -> sqlite3.Connection | None:
    path = (os.environ.get("PSDB")
            or os.path.join(base_dir, "appdata", "logs", "terminal_history.db"))
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _save_to_history(base_dir: str, filename: str, analysis: str,
                     cwd: str, has_findings: bool):
    """Insert a synthetic psscreenshot entry into terminal_history.db."""
    conn = _db_connect(base_dir)
    if conn is None:
        return
    ts = int(time.time())
    try:
        cur = conn.execute(
            "INSERT INTO commands (ts, ts_end, terminal, cmd, exit_code, output, cwd) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, ts, "psview", f"[psscreenshot: {filename}]", 0, analysis, cwd or None),
        )
        cmd_id = cur.lastrowid
        # Tag as "screenshot" only when model confirmed security-relevant findings
        if has_findings:
            conn.execute(
                "INSERT INTO command_tags (command_id, tag) VALUES (?, ?)",
                (cmd_id, "screenshot"),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


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
    parser.add_argument("-c", "--cmd",  action="store_true",
                        help="Output only the best command based on the image, no analysis text")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.image:
        print(
            "psview — AI-powered screenshot / image analyzer\n\n"
            "Usage:\n"
            "  psview <image>                          Analyze image with default pentest prompt\n"
            "  psview <image> \"<question>\"             Ask a specific question about the image\n"
            "  psview <image> -c, --cmd                Output only the best command (no analysis)\n"
            "  psview -p, --profile <name> <image>     Use a specific saved profile\n\n"
            "Supported formats: PNG, JPG, JPEG, WebP, GIF\n\n"
            "Requires a vision-capable model (Claude, GPT-4o, llava, moondream, etc.).\n"
            "The analysis is saved to terminal history so psnext/psreport can use it.\n"
            "If the model detects security-relevant findings, the entry is tagged 'findings'.\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    cwd = (args.cwd or "").strip()

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
    use_tools        = _ai._tools_enabled(profile, base_dir)

    _CMD_TOOL = {
        "name":        "suggest_command",
        "description": "Return the single most important shell command to run based on the image analysis",
        "parameters": {
            "type":       "object",
            "properties": {
                "command": {
                    "type":        "string",
                    "description": "The shell command to run, ready to execute as-is",
                }
            },
            "required": ["command"],
        },
    }

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

    # For --cmd text path: append command instruction (no Findings marker needed)
    cmd_question = question
    if args.cmd and not use_tools:
        cmd_question = (
            question + "\n\n"
            "At the very end, on a new line, write ONLY the single most important command "
            "to run based solely on what you see in this image — "
            "no prefix, no explanation, no backticks, just the raw command."
        )

    messages = _build_messages(b64, media_type, cmd_question, provider)

    # ── --cmd mode: command only, no analysis output ───────────────────────────
    if args.cmd:
        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info(f"Analyzing {filename}...\n")
        if use_tools:
            cmd = _ai._run_llm_tool_call(provider, model, messages, _CMD_TOOL, url, api_key)
            if cmd:
                print(cmd)
        else:
            import io as _io
            _real_stdout = sys.stdout
            _real_stderr = sys.stderr
            sys.stdout   = _io.StringIO()
            sys.stderr   = _io.StringIO()
            try:
                response = _ai._run_llm(provider, model, messages, url, api_key,
                                        disable_thinking, custom_params, hide_thinking)
            finally:
                sys.stdout = _real_stdout
                sys.stderr = _real_stderr
            if response:
                cmd = _clean_command(response)
                if cmd:
                    print(cmd)
        sys.exit(0)

    # ── Stream analysis ────────────────────────────────────────────────────────
    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info(f"Analyzing {filename}...\n")

    analysis = _ai._run_llm(provider, model, messages, url, api_key,
                            disable_thinking, custom_params, hide_thinking)

    if not analysis:
        _ai._err("No response from model.")
        sys.exit(1)

    # ── Parse and strip Findings marker ───────────────────────────────────────
    has_findings, clean_analysis = _parse_findings_marker(analysis)

    # ── Save full clean analysis to history ────────────────────────────────────
    _save_to_history(base_dir, filename, clean_analysis, cwd, has_findings)
    findings_note = " [findings tagged]" if has_findings else ""
    _ai._info(f"\nSaved to terminal history as [psscreenshot: {filename}]{findings_note}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
