#!/usr/bin/env python3
"""
psreport.py — AI-powered pentest report generator for PurrSh3ll.
Filters terminal_history.jsonl for security-relevant entries and generates
a structured Markdown report saved to appmodules/Cyb3rCollector/reports/.
"""

import json
import os
import platform
import sys
from datetime import datetime

_HISTORY_TOKENS  = 12_000   # token budget for filtered history
_OUTPUT_PER_ENTRY = 800     # max output chars per history entry

# ── Pentest tool keywords (cmd must CONTAIN one of these) ──────────────────────
_TOOL_PATTERNS = {
    # Network scanning
    "nmap", "masscan", "rustscan", "unicornscan", "zmap", "arp-scan",
    # Web
    "gobuster", "dirbuster", "dirb", "nikto", "wfuzz", "ffuf",
    "feroxbuster", "sqlmap", "nuclei", "whatweb", "wafw00f", "wpscan",
    "droopescan", "joomscan", "burp", "zaproxy",
    # SMB / AD / LDAP
    "enum4linux", "crackmapexec", "cme", "smbclient", "smbmap",
    "rpcclient", "ldapsearch", "ldapenum", "bloodhound", "sharphound",
    "kerbrute", "impacket", "secretsdump", "psexec", "wmiexec",
    "smbexec", "atexec", "dcomexec", "evil-winrm", "pwncat",
    # Password / hash
    "hydra", "medusa", "hashcat", "john", "credmaster", "spray",
    "patator", "brutespray",
    # Exploitation
    "msfconsole", "msfvenom", "searchsploit", "exploitdb",
    # Post-exploitation / tunnelling
    "netcat", "socat", "chisel", "ligolo", "proxychains",
    # Recon / OSINT
    "theHarvester", "recon-ng", "maltego", "amass", "subfinder",
    "dnsrecon", "dnsenum", "fierce", "sublist3r",
    # Wireless
    "aircrack", "airodump", "aireplay", "kismet", "wifite",
    # Shell / misc pentest helpers
    "nc -", "nc -e", "bash -i", "python -c", "python3 -c",
    "perl -e", "ruby -e", "php -r",
    "wget http", "curl http", "curl -s",
    "ssh ", "ftp ", "telnet ",
    # Privilege escalation helpers
    "linpeas", "winpeas", "linenum", "pspy", "sudo -l",
    "find / -perm", "find / -suid", "getcap",
    # Host info (valuable in pentest context)
    "ifconfig", "ip addr", "ip route", "arp ", "netstat", "ss -",
    "whoami", "id ", "hostname", "uname -", "cat /etc/passwd",
    "cat /etc/shadow", "cat /etc/hosts",
}

# ── Output keywords that flag an entry as interesting ─────────────────────────
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

# ── Commands to always skip (pure noise) ──────────────────────────────────────
_SKIP_EXACT = {
    "ls", "ll", "la", "l", "pwd", "clear", "cls", "history",
    "exit", "logout", "man", "help",
}
_SKIP_PREFIXES = ("echo ", "printf ", "cat --help", "man ", "less ", "more ")


def _is_pentest_relevant(cmd: str, output: str, exit_code: int) -> bool:
    cmd_l   = cmd.lower().strip()
    out_l   = output.lower()

    # Skip pure noise
    if cmd_l in _SKIP_EXACT:
        return False
    if cmd_l.startswith(_SKIP_PREFIXES):
        return False

    # Keep if command matches a known tool
    for pattern in _TOOL_PATTERNS:
        if pattern in cmd_l:
            return True

    # Keep if non-zero exit (failures are informative)
    if exit_code != 0:
        return True

    # Keep if output contains security keywords
    for kw in _OUTPUT_KEYWORDS:
        if kw in out_l:
            return True

    return False


def _load_filtered_history(base_dir: str, token_budget: int, full: bool, _ai) -> tuple[str, int, int]:
    """Load and optionally filter terminal history within token budget.
    Returns (formatted_history, entries_loaded, entries_total)."""
    path = os.path.join(base_dir, "appdata", "logs", "terminal_history.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return "", 0, 0
    except Exception:
        return "", 0, 0

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

    # Walk newest → oldest within budget, then reverse for chronological display
    collected = []
    used = 0
    for entry in reversed(entries):
        ec     = entry.get("exit_code", 0)
        cmd    = entry.get("cmd", "")
        out    = entry.get("output", "")[:_OUTPUT_PER_ENTRY]
        cwd    = entry.get("cwd", "")
        ts     = entry.get("ts", 0)
        status = f"exit {ec}" if ec != 0 else "ok"

        part = f"$ {cmd} [{status}]"
        if cwd:
            part += f"  # cwd: {cwd}"
        if ts:
            part += f"  @ {datetime.fromtimestamp(ts).strftime('%H:%M:%S')}"
        if out:
            part += f"\n{out}"

        tokens = _ai._count_tokens(part)
        if used + tokens > token_budget:
            break
        collected.append(part)
        used += tokens

    if not collected:
        return "", 0, total
    return "\n".join(reversed(collected)), len(collected), total


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psreport", add_help=False)
    parser.add_argument("--target",   default=None, metavar="TARGET",
                        help="Target host/network/name for the report header")
    parser.add_argument("--title",    default=None, metavar="TITLE",
                        help="Custom report title")
    parser.add_argument("--full",     action="store_true",
                        help="Include full history without smart filtering")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("--cwd",      default=None, metavar="DIR")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psreport — AI-powered pentest report generator\n\n"
            "Usage:\n"
            "  psreport                             Generate report from filtered history\n"
            "  psreport --full                      Include full history (no filter)\n"
            "  psreport --target 192.168.1.0/24     Set target in report header\n"
            "  psreport --title \"Internal Pentest\"   Set custom report title\n\n"
            "Report is saved to appmodules/Cyb3rCollector/reports/\n"
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

    # ── Load history ───────────────────────────────────────────────────────────
    history, loaded, total = _load_filtered_history(base_dir, _HISTORY_TOKENS, args.full, _ai)
    if not history:
        _ai._err("No relevant history found — run some pentest commands first.")
        sys.exit(1)

    mode_label = "full" if args.full else "filtered"
    _ai._info(f"Loaded {loaded}/{total} history entries ({mode_label}).\n")

    # ── Build prompt ───────────────────────────────────────────────────────────
    now       = datetime.now()
    sys_info  = f"{platform.system()} {platform.release()} ({platform.machine()})"
    target    = (args.target or "").strip() or "Unknown"
    title     = (args.title or "").strip()  or "Penetration Test Report"
    cwd       = (args.cwd or "").strip()

    prompt  = f"System: {sys_info}\n"
    prompt += f"Date: {now.strftime('%Y-%m-%d %H:%M')}\n"
    prompt += f"Target: {target}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    prompt += f"\nTerminal session history ({loaded} security-relevant commands):\n{history}\n"
    prompt += f"""
You are an expert penetration tester writing a professional report.
Based solely on the terminal history above, generate a structured Markdown report.

Use exactly this structure:

# {title}
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
*Report generated by psreport — verify and complete before delivery.*

Be specific and extract concrete data (IPs, ports, service versions, hashes) directly from the history output. Mark sections as "[No data found]" if there is no evidence. Do not invent findings.
"""

    # ── Stream to terminal ─────────────────────────────────────────────────────
    _ai._info(f"Generating report...\n")
    messages = [{"role": "user", "content": prompt}]
    response = _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)

    if not response:
        _ai._err("No response from model.")
        sys.exit(1)

    # ── Save to file ───────────────────────────────────────────────────────────
    reports_dir = os.path.join(base_dir, "appmodules", "Cyb3rCollector", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename    = f"report_{now.strftime('%Y-%m-%d_%H-%M')}.md"
    report_path = os.path.join(reports_dir, filename)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(response)
        _ai._info(f"\nReport saved: {os.path.relpath(report_path, base_dir)}\n")
    except Exception as e:
        _ai._err(f"Failed to save report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
