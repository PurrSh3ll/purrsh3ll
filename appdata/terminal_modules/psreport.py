#!/usr/bin/env python3
"""
psreport.py — AI-powered pentest report generator for PurrSh3ll.
Filters terminal_history.jsonl for security-relevant entries and generates
a structured Markdown/HTML report saved to appmodules/Cyb3rCollector/reports/.

Modes:
  default  — smart-filter history, single LLM call (fast, ~12k tokens)
  --deep   — Map-Reduce: chunk full history, extract findings per chunk,
             combine into report (thorough, N+1 LLM calls)
"""

import io
import json
import os
import platform
import sys
from datetime import datetime

_OUTPUT_PER_ENTRY = 800   # max output chars per history entry
_HISTORY_LIMIT    = 40    # max entries for standard mode

# ── Pentest tool keywords ──────────────────────────────────────────────────────
_TOOL_PATTERNS = {
    # psview synthetic screenshot entries — always captured
    "psscreenshot",
    # Network scanning
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

_SKIP_EXACT    = {"ls", "ll", "la", "l", "pwd", "clear", "cls", "history", "exit", "logout", "man", "help"}
_SKIP_PREFIXES = ("echo ", "printf ", "cat --help", "man ", "less ", "more ")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_pentest_relevant(cmd: str, output: str, exit_code: int) -> bool:
    cmd_l = cmd.lower().strip()
    out_l = output.lower()
    if cmd_l in _SKIP_EXACT:
        return False
    if cmd_l.startswith(_SKIP_PREFIXES):
        return False
    for pattern in _TOOL_PATTERNS:
        if pattern in cmd_l:
            return True
    if exit_code != 0:
        return True
    for kw in _OUTPUT_KEYWORDS:
        if kw in out_l:
            return True
    return False


def _format_entry(entry: dict) -> str:
    ec     = entry.get("exit_code", 0)
    cmd    = entry.get("cmd", "")
    out    = entry.get("output", "")[:_OUTPUT_PER_ENTRY]
    cwd    = entry.get("cwd", "")
    ts     = entry.get("ts", 0)
    status = f"exit {ec}" if ec != 0 else "ok"
    part   = f"$ {cmd} [{status}]"
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


def _load_entries(base_dir: str, full: bool) -> tuple[list[dict], int]:
    """Load all history entries (optionally filtered). Returns (entries, total_raw)."""
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception:
        return [], 0

    entries = []
    for l in lines:
        try:
            entries.append(json.loads(l))
        except Exception:
            pass

    total = len(entries)
    if not full:
        entries = [e for e in entries
                   if _is_pentest_relevant(e.get("cmd", ""), e.get("output", ""), e.get("exit_code", 0))]
    return entries, total




def _run_silent(fn):
    """Call fn() with stdout suppressed, return its result."""
    buf = io.StringIO()
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
    parser.add_argument("--target",   default=None, metavar="TARGET")
    parser.add_argument("--title",    default=None, metavar="TITLE")
    parser.add_argument("--full",     action="store_true",
                        help="Include full history without smart filtering")
    parser.add_argument("--verbose",  action="store_true",
                        help="Stream report to terminal while saving (default: save only)")
    parser.add_argument("--format",   default="md", choices=["md", "html"])
    parser.add_argument("--deep",     action="store_true",
                        help="Map-Reduce mode: chunk entire history for thorough analysis")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-p", "-m", "--profile", "--model", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psreport — AI-powered pentest report generator\n\n"
            "Usage:\n"
            "  psreport                              Generate report from filtered history\n"
            "  psreport --deep                       Map-Reduce: thorough, chunks full history\n"
            "  psreport --full                       Include full history without smart filter\n"
            "  psreport --verbose                    Stream report to terminal while saving\n"
            "  psreport --format html                Generate HTML report instead of Markdown\n"
            "  psreport --target 192.168.1.0/24      Set target in report header\n"
            "  psreport --title \"Internal Pentest\"    Set custom report title\n"
            "  psreport -m <profile>                 Use a specific saved profile\n\n"
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

    now    = datetime.now()
    fmt    = args.format
    target = (args.target or "").strip() or "Unknown"
    title  = (args.title  or "").strip() or "Penetration Test Report"
    cwd    = (args.cwd    or "").strip()

    def _llm(messages, verbose=False):
        if verbose:
            return _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
        return _run_silent(
            lambda: _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)
        )

    sys_info   = f"{platform.system()} {platform.release()} ({platform.machine()})"
    template   = _report_template_html(title, target, now) if fmt == "html" else _report_template_md(title, target, now)
    fmt_name   = "HTML" if fmt == "html" else "Markdown"

    # ══════════════════════════════════════════════════════════════════════════
    # DEEP MODE — full history, single call
    # ══════════════════════════════════════════════════════════════════════════
    if args.deep:
        entries, total_raw = _load_entries(base_dir, args.full)
        if not entries:
            _ai._err("No relevant history found — run some pentest commands first.")
            sys.exit(1)

        mode_label = "full" if args.full else "filtered"
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
        prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\nTarget: {target}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        prompt += f"\nFull terminal session history ({len(entries)} entries):\n{history}\n"
        prompt += (
            f"\nYou are an expert penetration tester writing a professional report. "
            f"Based solely on the terminal history above, generate a complete {fmt_name} report "
            f"using exactly this template. Fill each section with concrete data extracted "
            f"from the history. Mark sections as '[No data found]' if no evidence. "
            f"Do not invent findings.\n\n{template}"
        )

        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info("Generating report...\n")
        messages = [{"role": "user", "content": prompt}]
        response = _llm(messages, verbose=args.verbose)

    # ══════════════════════════════════════════════════════════════════════════
    # STANDARD MODE — last 40 entries, single call
    # ══════════════════════════════════════════════════════════════════════════
    else:
        entries, total = _load_entries(base_dir, args.full)
        if not entries:
            _ai._err("No relevant history found — run some pentest commands first.")
            sys.exit(1)

        recent     = entries[-_HISTORY_LIMIT:]
        history    = "\n".join(_format_entry(e) for e in recent)
        loaded     = len(recent)
        mode_label = "full" if args.full else "filtered"
        _ai._info(f"Loaded {loaded}/{total} history entries ({mode_label}).\n")

        prompt = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\nTarget: {target}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        prompt += f"\nTerminal session history ({loaded} entries):\n{history}\n"
        prompt += (
            f"\nYou are an expert penetration tester writing a professional report. "
            f"Based solely on the terminal history above, generate a complete {fmt_name} report "
            f"using exactly this template. Fill each section with concrete data extracted "
            f"from the history. Mark sections as '[No data found]' if no evidence. "
            f"Do not invent findings.\n\n{template}"
        )

        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info("Generating report...\n")
        messages = [{"role": "user", "content": prompt}]
        response = _llm(messages, verbose=args.verbose)

    # ── Save to file ───────────────────────────────────────────────────────────
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
