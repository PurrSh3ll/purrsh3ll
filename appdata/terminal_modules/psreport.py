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
import re
import sqlite3
import sys
from datetime import datetime


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
    limit: int | None = None,
) -> tuple[list[sqlite3.Row], int]:
    """
    Load pentest-relevant commands from SQLite.

    Filtering:
      1. Commands tagged by auto_tagger → always included
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

        relevant = []
        for r in rows:
            if r["tags"]:
                relevant.append(r)
            elif _is_pentest_relevant(r["cmd"], r["output"] or "", r["exit_code"]):
                relevant.append(r)
        rows = relevant

        # Deduplicate: keep only the most recent execution of each unique command.
        seen: dict[str, sqlite3.Row] = {}
        for r in rows:
            cmd = r["cmd"]
            if cmd not in seen or r["ts"] > seen[cmd]["ts"]:
                seen[cmd] = r
        rows = sorted(seen.values(), key=lambda r: r["ts"])

        if limit:
            rows = rows[-limit:]

        return rows, total
    finally:
        conn.close()


def _format_entry(row: sqlite3.Row) -> str:
    ec     = row["exit_code"]
    cmd    = row["cmd"] or ""
    status = f"exit {ec}" if ec not in (0, None) else "ok"
    return f"$ {cmd} [{status}]"


def _confirm_send(prompt: str, n_entries: int, total: int,
                  mode_label: str, profile: dict, base_dir: str) -> bool:
    """Print token estimate + context fit, ask Continue? [y/n], return True if confirmed."""
    import math as _math
    est_tokens = len(prompt) // 4
    ctx_window = _ai._get_ctx_window(profile, base_dir)

    lines = [
        f"\n  Entries : {n_entries}/{total} ({mode_label})",
        f"  Prompt  : ~{est_tokens:,} tokens  ({len(prompt):,} chars)",
    ]
    if ctx_window:
        if est_tokens <= ctx_window:
            pct = int(est_tokens / ctx_window * 100)
            lines.append(f"  Context : {ctx_window:,} tokens — fits ({pct}% used)")
        else:
            chunks = _math.ceil(est_tokens / ctx_window)
            lines.append(
                f"  Context : {ctx_window:,} tokens — \033[33mEXCEEDS by "
                f"{est_tokens - ctx_window:,} tokens ({chunks}x context)\033[0m"
            )
            lines.append(
                f"  \033[33mWarning : prompt may be truncated or refused by the model.\033[0m"
            )
            lines.append(
                f"  \033[33m          Use --compress (coming soon) to reduce prompt size.\033[0m"
            )
    else:
        lines.append(f"  Context : unknown (model not in registry)")

    lines.append(f"\nContinue? [y/n] ")
    sys.stderr.write("\n".join(lines))
    sys.stderr.flush()
    try:
        reply = sys.stdin.readline().strip()
    except Exception:
        reply = ""
    if reply.lower() != "y":
        sys.stderr.write("Aborted.\n")
        return False
    return True


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


# ── Notes mode helpers ────────────────────────────────────────────────────────

_STOP_WORDS = {
    "the", "and", "for", "with", "from", "that", "this", "was", "are", "has",
    "have", "had", "been", "using", "used", "via", "port", "into", "onto",
    "then", "when", "also", "able", "after", "found", "show", "shows",
    "there", "their", "where", "which", "will", "would", "could", "should",
    "running", "access", "target",
}


def _extract_tokens(text: str) -> list[str]:
    """Extract meaningful search tokens from text (marker content or notes).
    Preserves IPs, CVEs, hashes as atomic units; splits rest into words."""
    tokens: list[str] = []
    # Atomic: IPs (with optional CIDR)
    tokens += re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b', text)
    # Atomic: CVE IDs
    tokens += re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    # Atomic: hex hashes (md5/sha1/sha256)
    tokens += re.findall(r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b',
                         text, re.IGNORECASE)
    # Words: split on non-alphanumeric (keep hyphens/underscores inside words)
    for w in re.split(r'[^a-zA-Z0-9_\-]+', text):
        w = w.strip('-_').lower()
        if len(w) > 3 and w not in _STOP_WORDS:
            tokens.append(w)
    # Deduplicate preserving order
    seen: set[str] = set()
    result: list[str] = []
    for t in tokens:
        tl = t.lower()
        if tl not in seen:
            seen.add(tl)
            result.append(t)
    return result


def _snapshot_history(conn: sqlite3.Connection) -> list[dict]:
    """Snapshot all pentest-relevant commands at report-generation time.
    Returns list of plain dicts (immune to connection lifecycle)."""
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
    result = []
    for r in rows:
        if r["tags"] or _is_pentest_relevant(r["cmd"], r["output"] or "", r["exit_code"]):
            result.append(dict(r))
    return result


def _search_evidence(snapshot: list[dict], query: str,
                     max_results: int = 3, min_score: int = 1) -> list[dict]:
    """OR-score snapshot rows against query tokens, return top matches."""
    tokens = _extract_tokens(query)
    if not tokens:
        return []
    scored = []
    for row in snapshot:
        haystack = ((row["cmd"] or "") + " " + (row["output"] or "")).lower()
        score = sum(1 for t in tokens if t.lower() in haystack)
        if score >= min_score:
            scored.append((score, row["ts"] or 0, row))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [r for _, _, r in scored[:max_results]]


def _format_evidence_block(rows: list[dict]) -> str:
    """Format matched snapshot rows as a fenced markdown blockquote."""
    if not rows:
        return "> *\\[No terminal evidence found\\]*\n"
    parts = []
    for row in rows:
        ts_str = ""
        if row.get("ts"):
            try:
                ts_str = f" *({datetime.fromtimestamp(row['ts']).strftime('%Y-%m-%d %H:%M:%S')})*"
            except Exception:
                pass
        ec     = row.get("exit_code")
        status = f"exit {ec}" if ec not in (0, None) else "ok"
        tags   = f"  [{row['tags']}]" if row.get("tags") else ""
        out    = (row.get("output") or "").strip()
        # cap output: 25 lines or 600 chars
        out_lines = out.splitlines()[:25]
        out = "\n".join(out_lines)
        if len(out) > 600:
            out = out[:600] + "\n...truncated..."

        block  = f"> **Terminal Evidence**{ts_str}\n"
        block += f"> ```\n"
        block += f"> $ {row['cmd']} [{status}]{tags}\n"
        if out:
            for line in out.splitlines():
                block += f"> {line}\n"
        block += "> ```"
        parts.append(block)
    return "\n>\n".join(parts) + "\n"


def _resolve_placeholders(text: str, snapshot: list[dict]) -> str:
    """Replace <!-- PSEVIDENCE: ... --> markers with real terminal evidence.

    Each unique command row is injected at most once across the whole report
    (deduplication by row id) to prevent the same evidence block from
    appearing in every section.  Requires at least 2 matching tokens so that
    single-word queries do not pull in unrelated commands.
    """
    pattern  = re.compile(r'<!--\s*PSEVIDENCE:\s*(.*?)\s*-->', re.IGNORECASE | re.DOTALL)
    used_ids: set[int] = set()

    def _replace(m: re.Match) -> str:
        query    = m.group(1).strip()
        rows     = _search_evidence(snapshot, query, max_results=2, min_score=2)
        new_rows = [r for r in rows if r["id"] not in used_ids]
        if not new_rows:
            return ""
        used_ids.update(r["id"] for r in new_rows)
        return "\n\n" + _format_evidence_block(new_rows)

    return pattern.sub(_replace, text)


def _build_snapshot_summary(snapshot: list[dict]) -> str:
    """Build a short summary of snapshot for the LLM prompt."""
    if not snapshot:
        return ""
    from collections import Counter
    phase_counts: Counter = Counter()
    for row in snapshot:
        if row.get("tags"):
            for tag in row["tags"].split(", "):
                tag = tag.strip()
                if tag:
                    phase_counts[tag] += 1
    ts_vals = [r["ts"] for r in snapshot if r.get("ts")]
    time_range = ""
    if ts_vals:
        try:
            t0 = datetime.fromtimestamp(min(ts_vals)).strftime("%Y-%m-%d %H:%M")
            t1 = datetime.fromtimestamp(max(ts_vals)).strftime("%Y-%m-%d %H:%M")
            time_range = f"\nTime range: {t0} → {t1}"
        except Exception:
            pass
    phase_str = ""
    if phase_counts:
        phase_str = "\nPhases: " + ", ".join(
            f"{tag} ({cnt})" for tag, cnt in phase_counts.most_common(10)
        )
    return (
        f"[TERMINAL SNAPSHOT]\n"
        f"Commands captured: {len(snapshot)}{time_range}{phase_str}\n"
        f"Insert <!-- PSEVIDENCE: <search terms> --> markers where terminal "
        f"evidence supports a claim."
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psreport", add_help=False)
    parser.add_argument("-t", "--target",  default=None, metavar="TARGET")
    parser.add_argument("-T", "--title",   default=None, metavar="TITLE")
    parser.add_argument("-n", "--notes",   default=None, metavar="FILE",
                        help="Path to pentester notes file — AI generates report enriched "
                             "with terminal evidence via <!-- PSEVIDENCE: --> placeholders")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Stream report to terminal while saving (default: save only)")
    parser.add_argument("-f", "--format",  default="md", choices=["md", "html"])
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
            "  psreport                                    Generate report from terminal history\n"
            "  psreport -n, --notes notes.txt              Notes-mode: report from your notes + terminal evidence\n"
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
    # NOTES MODE — report from pentester notes + placeholder evidence injection
    # ══════════════════════════════════════════════════════════════════════════
    if args.notes:
        notes_path = os.path.expanduser(args.notes)
        if not os.path.isfile(notes_path):
            _ai._err(f"Notes file not found: {notes_path}")
            sys.exit(1)
        try:
            with open(notes_path, encoding="utf-8", errors="replace") as _nf:
                notes_text = _nf.read().strip()
        except Exception as e:
            _ai._err(f"Cannot read notes file: {e}")
            sys.exit(1)
        if not notes_text:
            _ai._err("Notes file is empty.")
            sys.exit(1)

        # Snapshot terminal history at this exact moment
        conn_snap = _db_connect(base_dir)
        snapshot: list[dict] = []
        if conn_snap:
            try:
                snapshot = _snapshot_history(conn_snap)
            finally:
                conn_snap.close()

        # Intel header (attack surface, findings, phases)
        conn_hdr = _db_connect(base_dir)
        intel_header = ""
        if conn_hdr:
            try:
                intel_header = _build_intel_header(conn_hdr, target)
            finally:
                conn_hdr.close()

        snap_summary = _build_snapshot_summary(snapshot)

        _ai._info(
            f"Notes mode: {os.path.basename(notes_path)}  "
            f"({len(snapshot)} terminal entries in snapshot)\n"
        )

        prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
        prompt += f"Target: {target or 'Unknown'}\n"
        if cwd:
            prompt += f"Working directory: {cwd}\n"
        prompt += f"\n[PENTESTER NOTES]\n{notes_text}\n"
        if intel_header:
            prompt += f"\n{intel_header}\n"
        if snap_summary:
            prompt += f"\n{snap_summary}\n"
        prompt += f"""
[INSTRUCTIONS]
You are an expert penetration tester writing a professional report.
The pentester's notes above are your PRIMARY source of truth.
The intelligence summary provides structured data to complement the notes.

For every specific finding, exploitation step, or discovered asset that you
write about in the report, insert a placeholder marker on its own line
immediately after the relevant sentence:

    <!-- PSEVIDENCE: <specific search terms> -->

The application will replace these markers with the actual terminal command
and its output from the session database, including timestamp.
Use precise, specific terms — IP addresses, tool names, CVE IDs, service
names, port numbers, hash values, usernames.

Good marker examples:
    <!-- PSEVIDENCE: nmap 192.168.1.10 port 445 smb -->
    <!-- PSEVIDENCE: hydra brute force ssh admin password -->
    <!-- PSEVIDENCE: ms17-010 eternalblue meterpreter shell -->
    <!-- PSEVIDENCE: linpeas suid privesc root -->
    <!-- PSEVIDENCE: sqlmap database dump credentials -->

Aim for 2–4 markers per major finding. Do not invent terminal outputs.
If you write about something that likely has no terminal evidence
(e.g. manual browser testing), omit the marker.

Generate the complete {fmt_name} report below using exactly this template:

{template}"""

        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")
        _ai._info("Generating report from notes...\n")
        messages = [{"role": "user", "content": prompt}]
        response = _llm(messages, verbose=args.verbose)

        if not response:
            _ai._err("No response from model.")
            sys.exit(1)

        # Resolve <!-- PSEVIDENCE: ... --> placeholders with real terminal data
        _ai._info("Injecting terminal evidence...\n")
        resolved = _resolve_placeholders(response, snapshot)
        injected = response.count("<!-- PSEVIDENCE:") - resolved.count("<!-- PSEVIDENCE:")
        _ai._info(f"Evidence injected: {injected} placeholder(s) resolved.\n")

        reports_dir = os.path.join(base_dir, "appmodules", "Cyb3rCollector", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename    = f"report_{now.strftime('%Y-%m-%d_%H-%M')}.{fmt}"
        report_path = os.path.join(reports_dir, filename)
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(resolved)
            _ai._info(f"Report saved: {os.path.relpath(report_path, base_dir)}\n")
        except Exception as e:
            _ai._err(f"Failed to save report: {e}")
            sys.exit(1)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # STANDARD MODE — intel header + filtered commands (no output)
    # ══════════════════════════════════════════════════════════════════════════
    entries, total = _load_entries_sqlite(base_dir, limit=_ai._TERMINAL_HIST_LIMIT)
    if not entries and not intel_header:
        _ai._err("No relevant history found — run some pentest commands first.")
        sys.exit(1)

    commands = "\n".join(_format_entry(e) for e in entries)
    prompt   = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
    prompt  += f"Target: {target or 'Unknown'}\n"
    if cwd:
        prompt += f"Working directory: {cwd}\n"
    if intel_header:
        prompt += f"\n{intel_header}\n"
    if commands:
        prompt += f"\n[COMMANDS EXECUTED — last {len(entries)} entries]\n{commands}\n"
    prompt += (
        f"\nYou are an expert penetration tester writing a professional report. "
        f"Based on the intelligence summary and commands above, generate "
        f"a complete {fmt_name} report using exactly this template. Fill each "
        f"section with concrete data. Mark sections as '[No data found]' if no "
        f"evidence. Do not invent findings.\n\n{template}"
    )
    if not _confirm_send(prompt, len(entries), total, "filtered (tagged + keyword)", profile, base_dir):
        sys.exit(0)

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
