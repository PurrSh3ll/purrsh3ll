#!/usr/bin/env python3
"""
psreport.py — AI-powered pentest report generator for PurrSh3ll.
Reads terminal_history.db (SQLite) — tagged commands via tool_categories.json
(282 tools, 19 categories) plus fallback keyword filter — and generates a
structured Markdown/HTML report saved to appmodules/Cyb3rCollector/reports/.

Modes:
  default  — intel header + smart-filtered history, single LLM call (fast)
  --deep   — intel header + full history with tag annotations, single LLM call
"""

import io
import os
import platform
import sqlite3
import sys
from datetime import datetime

_OUTPUT_PER_ENTRY = 800   # max output chars per history entry in prompt

# ── Fallback filter for commands not in tool_categories.json ──────────────────

_SKIP_EXACT    = {"ls", "ll", "la", "l", "pwd", "clear", "cls", "history",
                  "exit", "logout", "man", "help"}
_SKIP_PREFIXES = ("echo ", "printf ", "cat --help", "man ", "less ", "more ")

_TOOL_PATTERNS = {
    "psscreenshot",
    "nmap", "masscan", "rustscan", "unicornscan", "zmap", "arp-scan",
    "gobuster", "dirbuster", "dirb", "nikto", "wfuzz", "ffuf",
    "feroxbuster", "sqlmap", "nuclei", "whatweb", "wafw00f", "wpscan",
    "droopescan", "joomscan", "burp", "zaproxy",
    "enum4linux", "crackmapexec", "cme", "smbclient", "smbmap",
    "rpcclient", "ldapsearch", "ldapenum", "bloodhound", "sharphound",
    "kerbrute", "impacket", "secretsdump", "psexec", "wmiexec",
    "smbexec", "atexec", "dcomexec", "evil-winrm", "pwncat",
    "hydra", "medusa", "hashcat", "john", "credmaster", "spray",
    "patator", "brutespray",
    "msfconsole", "msfvenom", "searchsploit", "exploitdb",
    "netcat", "socat", "chisel", "ligolo", "proxychains",
    "theHarvester", "recon-ng", "maltego", "amass", "subfinder",
    "dnsrecon", "dnsenum", "fierce", "sublist3r",
    "aircrack", "airodump", "aireplay", "kismet", "wifite",
    "nc -", "nc -e", "bash -i", "python -c", "python3 -c",
    "perl -e", "ruby -e", "php -r",
    "wget http", "curl http", "curl -s",
    "ssh ", "ftp ", "telnet ",
    "linpeas", "winpeas", "linenum", "pspy", "sudo -l",
    "find / -perm", "find / -suid", "getcap",
    "ifconfig", "ip addr", "ip route", "arp ", "netstat", "ss -",
    "whoami", "id ", "hostname", "uname -", "cat /etc/passwd",
    "cat /etc/shadow", "cat /etc/hosts",
}

_OUTPUT_KEYWORDS = {
    "password", "passwd", "credential", "hash", "ntlm", "lm:", "md5",
    "sha1", "sha256", "administrator", "admin", "root", "login",
    "cve-", "vulnerability", "vuln", "exploit", "payload",
    "open", "filtered", "closed", "service", "version",
    "ssh", "ftp", "http", "smb", "rdp", "winrm", "telnet",
    "found", "success", "valid", "invalid", "fail",
    "permission denied", "access denied", "forbidden",
    "token", "session", "cookie", "secret", "key",
}


def _is_pentest_relevant(cmd: str, output: str, exit_code) -> bool:
    """Fallback filter for commands not tagged by auto_tagger."""
    cmd_l = cmd.lower().strip()
    out_l = (output or "").lower()
    if cmd_l in _SKIP_EXACT:
        return False
    if cmd_l.startswith(_SKIP_PREFIXES):
        return False
    for pattern in _TOOL_PATTERNS:
        if pattern in cmd_l:
            return True
    if exit_code not in (0, None):
        return True
    for kw in _OUTPUT_KEYWORDS:
        if kw in out_l:
            return True
    return False


# ── SQLite helpers ─────────────────────────────────────────────────────────────

def _db_connect(base_dir: str) -> sqlite3.Connection | None:
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.db")
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _build_intel_header(conn: sqlite3.Connection, target_filter: str | None) -> str:
    """Build [ATTACK SURFACE] + [FINDINGS] + [PHASE COVERAGE] from SQLite."""
    parts = []

    # ── Attack surface ─────────────────────────────────────────────────────────
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
            """
        ).fetchall()

    targets: dict[str, dict] = {}
    for r in rows:
        ip = r["ip"]
        if ip not in targets:
            targets[ip] = {"hostname": r["hostname"], "os_guess": r["os_guess"], "ports": []}
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

    # ── Findings ───────────────────────────────────────────────────────────────
    finding_sections = []

    creds = conn.execute(
        "SELECT DISTINCT value, target, service FROM findings "
        "WHERE finding_type = 'credential' ORDER BY target, value"
    ).fetchall()
    if creds:
        lines = ["Credentials:"]
        for r in creds:
            line = f"  • {r['value']}"
            meta = [x for x in (r["target"], r["service"]) if x]
            if meta:
                line += f"  ({', '.join(meta)})"
            lines.append(line)
        finding_sections.append("\n".join(lines))

    users = conn.execute(
        "SELECT DISTINCT value FROM findings WHERE finding_type = 'user' ORDER BY value"
    ).fetchall()
    if users:
        finding_sections.append("Users:\n  " + ", ".join(r["value"] for r in users))

    hashes = conn.execute(
        "SELECT DISTINCT value, target FROM findings WHERE finding_type = 'hash' ORDER BY target, value"
    ).fetchall()
    if hashes:
        lines = ["Hashes:"]
        for r in hashes:
            line = f"  • {r['value']}"
            if r["target"]:
                line += f"  ({r['target']})"
            lines.append(line)
        finding_sections.append("\n".join(lines))

    flags = conn.execute(
        "SELECT DISTINCT value FROM findings WHERE finding_type = 'flag' ORDER BY value"
    ).fetchall()
    if flags:
        finding_sections.append("Flags:\n  " + ", ".join(r["value"] for r in flags))

    cves = conn.execute(
        "SELECT DISTINCT value FROM findings WHERE finding_type = 'cve' ORDER BY value"
    ).fetchall()
    if cves:
        finding_sections.append("CVEs:\n  " + ", ".join(r["value"] for r in cves))

    if finding_sections:
        parts.append("[FINDINGS]\n" + "\n".join(finding_sections))

    # ── Phase coverage ─────────────────────────────────────────────────────────
    all_phases = [
        "recon", "scan", "web", "smb", "ftp", "ssh", "ldap", "ad",
        "exploit", "privesc", "lateral", "crack", "shell",
        "network", "cloud", "forensics", "re", "wifi", "other",
    ]
    phase_rows = conn.execute(
        """
        SELECT ct.tag, COUNT(*) AS cnt, MAX(c.cmd) AS last_cmd
        FROM command_tags ct
        JOIN commands c ON c.id = ct.command_id
        WHERE ct.tag IN ({})
        GROUP BY ct.tag
        ORDER BY cnt DESC
        """.format(",".join("?" * len(all_phases))),
        all_phases,
    ).fetchall()

    used = {r["tag"] for r in phase_rows}
    missing = [p for p in all_phases if p not in used]

    if phase_rows or missing:
        section = ["[PHASE COVERAGE]"]
        for r in phase_rows:
            last = (r["last_cmd"] or "")[:80]
            section.append(f"  {r['tag']:<12} ({r['cnt']:>3} cmds)  last: {last}")
        if missing:
            section.append("  NOT YET: " + " · ".join(missing))
        parts.append("\n".join(section))

    return "\n\n".join(parts)


def _load_entries_sqlite(
    base_dir: str,
    full: bool = False,
    limit: int | None = None,
) -> tuple[list[sqlite3.Row], int]:
    """
    Load pentest-relevant commands from SQLite.

    Filtering strategy (unless --full):
      1. Commands tagged by auto_tagger (282 tools, 19 categories) → always included
      2. Untagged commands → fallback _is_pentest_relevant() filter

    Returns (rows_chronological, total_commands_in_db).
    """
    conn = _db_connect(base_dir)
    if conn is None:
        return [], 0

    try:
        total = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]

        rows = conn.execute(
            """
            SELECT c.id, c.ts, c.cmd, c.exit_code, c.output, c.cwd,
                   GROUP_CONCAT(ct.tag, ', ') AS tags
            FROM commands c
            LEFT JOIN command_tags ct ON ct.command_id = c.id
            GROUP BY c.id
            ORDER BY c.ts ASC
            """
        ).fetchall()

        if not full:
            relevant = []
            for r in rows:
                if r["tags"]:
                    relevant.append(r)
                elif _is_pentest_relevant(r["cmd"], r["output"] or "", r["exit_code"]):
                    relevant.append(r)
            rows = relevant

        if limit:
            rows = rows[-limit:]

        return rows, total
    finally:
        conn.close()


def _format_entry(row: sqlite3.Row) -> str:
    ec     = row["exit_code"]
    cmd    = row["cmd"] or ""
    out    = (row["output"] or "").strip()[:_OUTPUT_PER_ENTRY]
    cwd    = row["cwd"] or ""
    ts     = row["ts"] or 0
    tags   = row["tags"] or ""
    status = f"exit {ec}" if ec not in (0, None) else "ok"

    part = f"$ {cmd} [{status}]"
    if tags:
        part += f"  [{tags}]"
    if cwd:
        part += f"  # cwd: {cwd}"
    if ts:
        try:
            part += f"  @ {datetime.fromtimestamp(ts).strftime('%H:%M:%S')}"
        except Exception:
            pass
    if out:
        part += f"\n{out}"
    return part


def _run_silent(fn):
    buf  = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        return fn()
    finally:
        sys.stdout = real


def _report_template_md(title: str, target: str, now: datetime) -> str:
    return f"""# {title}
**Date:** {now.strftime('%Y-%m-%d')}
**Target:** {target}
**Tester:** [to be filled]
**Status:** Draft — requires review

---

## Executive Summary
[2-3 sentences: what was tested, key findings, overall risk level]

## Scope & Methodology
[Describe the scope inferred from commands and tools used]

## Discovered Assets
[Hosts, open ports, services, versions found — extract from nmap/scan output]

## Vulnerabilities & Findings
[List each finding with: name, severity (Critical/High/Medium/Low/Info), evidence from output]

## Credentials & Sensitive Data
[Any passwords, hashes, tokens, keys found in output]

## Timeline of Key Actions
[Chronological list of significant commands and their results]

## Recommendations
[Concrete remediation steps for each finding]

---
*Report generated by psreport — verify and complete before delivery.*"""


def _report_template_html(title: str, target: str, now: datetime) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 960px; margin: 40px auto; color: #222; }}
  h1 {{ color: #c0392b; }} h2 {{ color: #2c3e50; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
  .meta {{ color: #555; margin-bottom: 24px; }}
  .finding {{ background: #f9f9f9; border-left: 4px solid #e74c3c; padding: 8px 12px; margin: 8px 0; }}
  .severity-critical {{ border-color: #c0392b; }} .severity-high {{ border-color: #e67e22; }}
  .severity-medium {{ border-color: #f1c40f; }} .severity-low {{ border-color: #27ae60; }}
  .severity-info {{ border-color: #2980b9; }}
  code {{ background: #eee; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }}
  pre {{ background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; overflow-x: auto; }}
  footer {{ color: #999; font-size: 0.85em; margin-top: 40px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">
  <strong>Date:</strong> {now.strftime('%Y-%m-%d')}<br>
  <strong>Target:</strong> {target}<br>
  <strong>Tester:</strong> [to be filled]<br>
  <strong>Status:</strong> Draft — requires review
</div>
<h2>Executive Summary</h2>[2-3 sentences]
<h2>Scope &amp; Methodology</h2>[scope and tools used]
<h2>Discovered Assets</h2>[hosts, ports, services]
<h2>Vulnerabilities &amp; Findings</h2>[findings as div.finding with severity class]
<h2>Credentials &amp; Sensitive Data</h2>[passwords, hashes, tokens]
<h2>Timeline of Key Actions</h2>[significant commands as pre blocks]
<h2>Recommendations</h2>[remediation steps]
<footer>Report generated by psreport — verify and complete before delivery.</footer>
</body>
</html>"""


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psreport", add_help=False)
    parser.add_argument("-t", "--target",  default=None, metavar="TARGET")
    parser.add_argument("-T", "--title",   default=None, metavar="TITLE")
    parser.add_argument("--full",          action="store_true",
                        help="Include full history without smart filtering")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Stream report to terminal while saving (default: save only)")
    parser.add_argument("-f", "--format",  default="md", choices=["md", "html"])
    parser.add_argument("-d", "--deep",    action="store_true",
                        help="Deep mode: full history with tag annotations, single LLM call")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psreport — AI-powered pentest report generator\n\n"
            "Usage:\n"
            "  psreport                                    Generate report from filtered history\n"
            "  psreport -d, --deep                         Deep: full annotated history, single call\n"
            "  psreport --full                             Include full history without smart filter\n"
            "  psreport -v, --verbose                      Stream report to terminal while saving\n"
            "  psreport -f, --format html                  Generate HTML report instead of Markdown\n"
            "  psreport -t, --target 192.168.1.0/24        Set target in report header\n"
            "  psreport -T, --title \"Internal Pentest\"      Set custom report title\n"
            "  psreport -p, --profile <name>               Use a specific saved profile\n\n"
            "Report is saved to appmodules/Cyb3rCollector/reports/\n"
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

    now    = datetime.now()
    fmt    = args.format
    target = (args.target or "").strip() or None
    title  = (args.title  or "").strip() or "Penetration Test Report"
    cwd    = (args.cwd    or "").strip()

    def _llm(messages, verbose=False):
        if verbose:
            return _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
        return _run_silent(
            lambda: _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params, hide_thinking)
        )

    sys_info  = f"{platform.system()} {platform.release()} ({platform.machine()})"
    fmt_name  = "HTML" if fmt == "html" else "Markdown"
    template  = _report_template_html(title, target or "Unknown", now) if fmt == "html" \
                else _report_template_md(title, target or "Unknown", now)

    # ── Build intel header from SQLite structured tables ──────────────────────
    conn_for_header = _db_connect(base_dir)
    intel_header = ""
    if conn_for_header:
        try:
            intel_header = _build_intel_header(conn_for_header, target)
        finally:
            conn_for_header.close()

    # ══════════════════════════════════════════════════════════════════════════
    # DEEP MODE — full/filtered history with tag annotations
    # ══════════════════════════════════════════════════════════════════════════
    if args.deep:
        entries, total_raw = _load_entries_sqlite(base_dir, full=args.full)
        if not entries and not intel_header:
            _ai._err("No relevant history found — run some pentest commands first.")
            sys.exit(1)

        mode_label = "full" if args.full else "filtered (tagged + keyword)"
        sys.stderr.write(
            f"\nDeep mode:\n"
            f"  Entries: {len(entries)}/{total_raw} ({mode_label})\n\n"
            f"Continue? [y/n] "
        )
        sys.stderr.flush()
        try:
            reply = sys.stdin.readline().strip()
        except Exception:
            reply = ""
        if reply.lower() != "y":
            sys.stderr.write("Aborted.\n")
            sys.exit(0)

        history = "\n".join(_format_entry(e) for e in entries)
        prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
        prompt += f"Target: {target or 'Unknown'}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        if intel_header:
            prompt += f"\n{intel_header}\n"
        if history:
            prompt += f"\n[TERMINAL HISTORY — {len(entries)} entries]\n{history}\n"
        prompt += (
            f"\nYou are an expert penetration tester writing a professional report. "
            f"Based on the intelligence summary and terminal history above, generate "
            f"a complete {fmt_name} report using exactly this template. Fill each "
            f"section with concrete data. Mark sections as '[No data found]' if no "
            f"evidence. Do not invent findings.\n\n{template}"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # STANDARD MODE — last N pentest-relevant entries
    # ══════════════════════════════════════════════════════════════════════════
    else:
        entries, total = _load_entries_sqlite(
            base_dir, full=args.full, limit=_ai._TERMINAL_HIST_LIMIT
        )
        if not entries and not intel_header:
            _ai._err("No relevant history found — run some pentest commands first.")
            sys.exit(1)

        mode_label = "full" if args.full else "filtered (tagged + keyword)"
        loaded = len(entries)
        _ai._info(f"Loaded {loaded}/{total} history entries ({mode_label}).\n")

        history = "\n".join(_format_entry(e) for e in entries)
        prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
        prompt += f"Target: {target or 'Unknown'}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        if intel_header:
            prompt += f"\n{intel_header}\n"
        if history:
            prompt += f"\n[TERMINAL HISTORY — last {loaded} entries]\n{history}\n"
        prompt += (
            f"\nYou are an expert penetration tester writing a professional report. "
            f"Based on the intelligence summary and terminal history above, generate "
            f"a complete {fmt_name} report using exactly this template. Fill each "
            f"section with concrete data. Mark sections as '[No data found]' if no "
            f"evidence. Do not invent findings.\n\n{template}"
        )

    # ── LLM call ──────────────────────────────────────────────────────────────
    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info("Generating report...\n")
    messages  = [{"role": "user", "content": prompt}]
    response  = _llm(messages, verbose=args.verbose)

    # ── Save to file ──────────────────────────────────────────────────────────
    if not response:
        _ai._err("No response from model.")
        sys.exit(1)

    reports_dir = os.path.join(base_dir, "appmodules", "Cyb3rCollector", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename    = f"report_{now.strftime('%Y-%m-%d_%H-%M')}.{fmt}"
    report_path = os.path.join(reports_dir, filename)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(response)
        _ai._info(f"\nReport saved: {os.path.relpath(report_path, base_dir)}\n")
    except Exception as e:
        _ai._err(f"Failed to save report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
