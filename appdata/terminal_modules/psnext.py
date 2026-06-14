#!/usr/bin/env python3
"""
psnext.py — AI-powered pentest next-step advisor for PurrSh3ll.
Reads terminal_history.db (SQLite) and suggests the most promising next moves.
"""

import os
import platform
import sqlite3
import sys

# Phase tags defined in tool_categories.json / auto_tagger
_PENTEST_PHASES = [
    "recon", "scan", "web", "smb", "ftp", "ssh", "ldap", "ad",
    "exploit", "privesc", "lateral", "crack", "persistence", "shell",
    "network", "cloud", "forensics", "re", "wifi",
]

_OUTPUT_CAP = 400  # chars per command in [RECENT SESSION]


def _clean_command(text: str) -> str:
    """Extract the last meaningful shell command from AI response."""
    lines_raw = text.strip().splitlines()

    filtered = []
    in_fence = False
    in_think = False
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


def _db_connect(base_dir: str) -> sqlite3.Connection | None:
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.db")
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _build_prompt_context(base_dir: str, target_filter: str | None, recent_limit: int) -> tuple[str, bool]:
    """
    Build the structured 3-layer prompt context from SQLite.
    Returns (context_string, has_any_data).
    """
    conn = _db_connect(base_dir)
    if conn is None:
        return "", False

    try:
        parts = []

        # ── Layer 1a: Attack surface (targets + ports) ────────────────────────
        if target_filter:
            rows = conn.execute(
                """
                SELECT t.ip, t.hostname, t.os_guess,
                       tp.port, tp.protocol, tp.service, tp.version
                FROM targets t
                LEFT JOIN target_ports tp ON tp.target_id = t.id
                WHERE t.ip = ? OR t.hostname = ?
                ORDER BY tp.port
                """,
                (target_filter, target_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT t.ip, t.hostname, t.os_guess,
                       tp.port, tp.protocol, tp.service, tp.version
                FROM targets t
                LEFT JOIN target_ports tp ON tp.target_id = t.id
                ORDER BY t.ip, tp.port
                """,
            ).fetchall()

        # Group by target
        targets: dict[str, dict] = {}
        for r in rows:
            ip = r["ip"]
            if ip not in targets:
                targets[ip] = {
                    "hostname": r["hostname"],
                    "os_guess": r["os_guess"],
                    "ports": [],
                }
            if r["port"] is not None:
                targets[ip]["ports"].append(r)

        if targets:
            section = ["[ATTACK SURFACE]"]
            for ip, info in targets.items():
                header = ip
                meta = []
                if info["hostname"]:
                    meta.append(info["hostname"])
                if info["os_guess"]:
                    meta.append(info["os_guess"])
                if meta:
                    header += f"  ({' · '.join(meta)})"
                section.append(header)
                for p in info["ports"]:
                    line = f"  {p['port']}/{p['protocol']}"
                    if p["service"]:
                        line += f"   {p['service']}"
                    if p["version"]:
                        line += f"  {p['version'][:60]}"
                    section.append(line)
            parts.append("\n".join(section))

        # ── Layer 1b: Findings ────────────────────────────────────────────────
        finding_sections = []

        # credentials
        creds = conn.execute(
            "SELECT DISTINCT value, target, service FROM findings "
            "WHERE finding_type = 'credential' ORDER BY target, value",
        ).fetchall()
        if creds:
            lines = ["Credentials:"]
            for r in creds:
                line = f"  • {r['value']}"
                meta = []
                if r["target"]:
                    meta.append(r["target"])
                if r["service"]:
                    meta.append(r["service"])
                if meta:
                    line += f"  ({', '.join(meta)})"
                lines.append(line)
            finding_sections.append("\n".join(lines))

        # users
        users = conn.execute(
            "SELECT DISTINCT value FROM findings WHERE finding_type = 'user' ORDER BY value",
        ).fetchall()
        if users:
            finding_sections.append("Users:\n  " + ", ".join(r["value"] for r in users))

        # hashes
        hashes = conn.execute(
            "SELECT DISTINCT value, target FROM findings WHERE finding_type = 'hash' ORDER BY target, value",
        ).fetchall()
        if hashes:
            lines = ["Hashes:"]
            for r in hashes:
                line = f"  • {r['value']}"
                if r["target"]:
                    line += f"  ({r['target']})"
                lines.append(line)
            finding_sections.append("\n".join(lines))

        # flags
        flags = conn.execute(
            "SELECT DISTINCT value FROM findings WHERE finding_type = 'flag' ORDER BY value",
        ).fetchall()
        if flags:
            finding_sections.append("Flags:\n  " + ", ".join(r["value"] for r in flags))

        # CVEs
        cves = conn.execute(
            "SELECT DISTINCT value FROM findings WHERE finding_type = 'cve' ORDER BY value",
        ).fetchall()
        if cves:
            finding_sections.append("CVEs:\n  " + ", ".join(r["value"] for r in cves))

        if finding_sections:
            parts.append("[FINDINGS]\n" + "\n".join(finding_sections))

        # ── Layer 2: Phase coverage ───────────────────────────────────────────
        phase_rows = conn.execute(
            """
            SELECT ct.tag, COUNT(*) AS cnt, MAX(c.cmd) AS last_cmd
            FROM command_tags ct
            JOIN commands c ON c.id = ct.command_id
            WHERE ct.tag IN ({})
            GROUP BY ct.tag
            ORDER BY cnt DESC
            """.format(",".join("?" * len(_PENTEST_PHASES))),
            _PENTEST_PHASES,
        ).fetchall()

        used_phases = {r["tag"] for r in phase_rows}
        missing = [p for p in _PENTEST_PHASES if p not in used_phases]

        if phase_rows or missing:
            section = ["[PHASE COVERAGE]"]
            for r in phase_rows:
                last = r["last_cmd"][:80] if r["last_cmd"] else ""
                section.append(f"  {r['tag']:<12} ({r['cnt']:>3} cmds)  last: {last}")
            if missing:
                section.append("  NOT YET: " + " · ".join(missing))
            parts.append("\n".join(section))

        # ── Layer 3: Recent commands ──────────────────────────────────────────
        recent = conn.execute(
            "SELECT cmd, exit_code, output, cwd FROM commands ORDER BY ts DESC LIMIT ?",
            (recent_limit,),
        ).fetchall()

        if recent:
            section = [f"[RECENT SESSION — last {len(recent)} commands]"]
            for r in reversed(recent):
                ec     = r["exit_code"]
                status = f"exit {ec}" if ec not in (0, None) else "ok"
                line   = f"$ {r['cmd']} [{status}]"
                if r["cwd"]:
                    line += f"  # cwd: {r['cwd']}"
                out = (r["output"] or "").strip()
                if out:
                    if len(out) > _OUTPUT_CAP:
                        out = out[:_OUTPUT_CAP] + f"\n...output truncated ({len(r['output'])} chars)..."
                    line += f"\n{out}"
                section.append(line)
            parts.append("\n".join(section))

        has_data = bool(recent) or bool(targets) or bool(creds) or bool(users)
        return "\n\n".join(parts), has_data

    finally:
        conn.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psnext", add_help=False)
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-t", "--target", default=None, metavar="TARGET",
                        help="Target host/network for additional context")
    parser.add_argument("-r", "--rag",    action="store_true",
                        help="Enrich prompt with knowledge base context")
    parser.add_argument("-n", "--top-n",  type=int, default=5, metavar="N", dest="top_n",
                        help="Number of RAG chunks (default: 5, used with --rag)")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psnext — AI pentest next-step advisor\n\n"
            "Usage:\n"
            "  psnext                               Suggest next steps based on terminal history\n"
            "  psnext -t, --target 192.168.1.0/24  Include target context\n"
            "  psnext -r, --rag                    Enrich with knowledge base context\n"
            "  psnext -r --rag -n 8                Use 8 RAG chunks\n"
            "  psnext -p, --profile <name>         Use a specific saved profile\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    sys.path.insert(0, os.path.dirname(__file__))
    import psai as _ai

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

    target = (args.target or "").strip() or None
    cwd    = (args.cwd or "").strip()

    context, has_data = _build_prompt_context(base_dir, target, _ai._TERMINAL_HIST_LIMIT)
    if not has_data:
        _ai._err("No terminal history found — run some commands first.")
        sys.exit(1)

    sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

    # Optional RAG enrichment
    rag_context = ""
    if args.rag:
        rag_query = (target or "penetration testing next steps")
        chunks = _ai._rag_fetch_chunks(rag_query, base_dir, config, args.top_n)
        if chunks:
            rag_parts = []
            for i, ch in enumerate(chunks, 1):
                src     = ch["meta"].get("source", "")
                heading = ch["meta"].get("heading", "")
                label   = f"[{i}] {src}" + (f"  ({heading})" if heading else "")
                rag_parts.append(f"{label}\n{ch['text']}")
            rag_context = "[KNOWLEDGE BASE]\n" + "\n\n---\n\n".join(rag_parts)

    prompt = f"System: {sys_info}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    if target:
        prompt += f"Target filter: {target}\n"
    prompt += "\n"
    prompt += context
    if rag_context:
        prompt += f"\n\n{rag_context}"
    prompt += (
        "\n\n[TASK]\n"
        "You are an expert penetration tester"
        + (" working on a pentest engagement." if not rag_context else " working on a pentest engagement (knowledge base context provided above).")
        + "\n"
        "Based on the intelligence summary and recent session above:\n"
        "1. Briefly summarize what has been discovered and where things stand.\n"
        "2. Identify the most important gaps or opportunities not yet exploited.\n"
        "3. Suggest 3-5 concrete next steps with the exact commands to run, ordered by priority.\n"
        "Be specific, practical, and reference the actual IPs, credentials and services visible above.\n"
        "At the very end, on a new line, write ONLY the single most important command to run next "
        "— no prefix, no explanation, no backticks, just the raw command."
    )

    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info("Analyzing terminal history for next pentest steps...\n")
    messages = [{"role": "user", "content": prompt}]

    # Stream analysis to stderr (visible via 2>/dev/tty),
    # print the best command to stdout (captured by zsh $())
    _real_stdout = sys.stdout
    sys.stdout   = sys.stderr
    try:
        response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
    finally:
        sys.stdout = _real_stdout

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
