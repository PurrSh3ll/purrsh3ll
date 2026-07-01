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
import json
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


_PHASES_ORDER = [
    "recon", "scan", "web", "smb", "ftp", "ssh", "ldap", "ad",
    "exploit", "lateral", "crack", "shell", "privesc",
    "network", "cloud", "forensics", "re", "wifi", "other",
]


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
    path = (os.environ.get("PSDB")
            or os.path.join(base_dir, "appdata", "logs", "terminal_history.db"))
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

    # ── Findings (with source command link, optionally filtered by target) ────────
    finding_sections = []

    # When target_filter is set: show findings for that target OR findings with
    # no target recorded (NULL) — e.g. flags, CVEs, users discovered globally.
    _tf      = target_filter
    _tf_cond = "AND (f.target = ? OR f.target IS NULL)" if _tf else ""
    _tf_arg  = (_tf,) if _tf else ()

    def _src(r) -> str:
        """Return '  [cmd_id] $ cmd' annotation if source command is known."""
        cmd_id = r["cmd_id"] if "cmd_id" in r.keys() else None
        src    = r["src_cmd"] if "src_cmd" in r.keys() else None
        if cmd_id and src:
            return f"\n    from: [cmd:{cmd_id}] $ {src[:100]}"
        return ""

    creds = conn.execute(
        f"""
        SELECT f.value, f.target, f.service,
               f.command_id AS cmd_id,
               (SELECT c.cmd FROM commands c WHERE c.id = f.command_id) AS src_cmd
        FROM findings f
        WHERE f.finding_type = 'credential' {_tf_cond}
        GROUP BY f.value, f.target, f.service
        ORDER BY f.target, f.value
        """,
        _tf_arg,
    ).fetchall()
    if creds:
        lines = ["Credentials:"]
        for r in creds:
            line = f"  • {r['value']}"
            meta = [x for x in (r["target"], r["service"]) if x]
            if meta:
                line += f"  ({', '.join(meta)})"
            line += _src(r)
            lines.append(line)
        finding_sections.append("\n".join(lines))

    users = conn.execute(
        f"""
        SELECT f.value,
               f.command_id AS cmd_id,
               (SELECT c.cmd FROM commands c WHERE c.id = f.command_id) AS src_cmd
        FROM findings f
        WHERE f.finding_type = 'user' {_tf_cond}
        GROUP BY f.value
        ORDER BY f.value
        """,
        _tf_arg,
    ).fetchall()
    if users:
        lines = ["Users:"]
        for r in users:
            lines.append(f"  • {r['value']}" + _src(r))
        finding_sections.append("\n".join(lines))

    hashes = conn.execute(
        f"""
        SELECT f.value, f.target,
               f.command_id AS cmd_id,
               (SELECT c.cmd FROM commands c WHERE c.id = f.command_id) AS src_cmd
        FROM findings f
        WHERE f.finding_type = 'hash' {_tf_cond}
        GROUP BY f.value, f.target
        ORDER BY f.target, f.value
        """,
        _tf_arg,
    ).fetchall()
    if hashes:
        lines = ["Hashes:"]
        for r in hashes:
            line = f"  • {r['value']}"
            if r["target"]:
                line += f"  ({r['target']})"
            line += _src(r)
            lines.append(line)
        finding_sections.append("\n".join(lines))

    flags = conn.execute(
        f"""
        SELECT f.value,
               f.command_id AS cmd_id,
               (SELECT c.cmd FROM commands c WHERE c.id = f.command_id) AS src_cmd
        FROM findings f
        WHERE f.finding_type = 'flag' {_tf_cond}
        GROUP BY f.value
        ORDER BY f.value
        """,
        _tf_arg,
    ).fetchall()
    if flags:
        lines = ["Flags:"]
        for r in flags:
            lines.append(f"  • {r['value']}" + _src(r))
        finding_sections.append("\n".join(lines))

    cves = conn.execute(
        f"""
        SELECT f.value,
               f.command_id AS cmd_id,
               (SELECT c.cmd FROM commands c WHERE c.id = f.command_id) AS src_cmd
        FROM findings f
        WHERE f.finding_type = 'cve' {_tf_cond}
        GROUP BY f.value
        ORDER BY f.value
        """,
        _tf_arg,
    ).fetchall()
    if cves:
        lines = ["CVEs:"]
        for r in cves:
            lines.append(f"  • {r['value']}" + _src(r))
        finding_sections.append("\n".join(lines))

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
        SELECT ct.tag,
               COUNT(*) AS cnt,
               (SELECT c2.cmd
                  FROM commands c2
                  JOIN command_tags ct2 ON ct2.command_id = c2.id
                 WHERE ct2.tag = ct.tag
                 ORDER BY c2.ts DESC, c2.id DESC
                 LIMIT 1) AS last_cmd
        FROM command_tags ct
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
    limit_per_phase: int | None = None,
) -> tuple[list[sqlite3.Row], int]:
    """
    Load pentest-relevant commands from SQLite.

    Filtering:
      1. Commands tagged by auto_tagger → always included
      2. Untagged commands → fallback _is_pentest_relevant() filter

    limit_per_phase: when set, keep only the last N commands per primary phase
    tag (e.g. recon, scan, exploit).  Commands without any phase tag go into
    the 'other' bucket and are also capped at N.  All selected rows are then
    re-merged and sorted chronologically.

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
                   GROUP_CONCAT(ct.tag, ', ') AS tags,
                   (SELECT GROUP_CONCAT(sub.fs, ' | ')
                    FROM (SELECT finding_type || ':' || SUBSTR(value, 1, 60) AS fs
                          FROM findings WHERE command_id = c.id LIMIT 3) sub
                   ) AS findings_summary
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

        if limit_per_phase:
            # Group by primary phase tag (same logic as _group_entries_by_phase).
            # Take the last N from each group, then re-merge chronologically.
            phase_buckets: dict[str, list] = {}
            for r in rows:
                tags = [t.strip() for t in (r["tags"] or "").split(",") if t.strip()]
                primary = next((p for p in _PHASES_ORDER if p in tags), "other")
                phase_buckets.setdefault(primary, []).append(r)
            selected = []
            for bucket in phase_buckets.values():
                selected.extend(bucket[-limit_per_phase:])
            rows = sorted(selected, key=lambda r: r["ts"])

        return rows, total
    finally:
        conn.close()


def _status_str(exit_code) -> str:
    """Human status for a command row. exit_code IS NULL means the command is
    still running — the two-phase logger inserts the row at start and finalizes
    it at end, so a NULL exit code is a live process, not a success."""
    if exit_code is None:
        return "running"
    return "ok" if exit_code == 0 else f"exit {exit_code}"


def _format_entry(row: sqlite3.Row) -> str:
    ec     = row["exit_code"]
    cmd    = row["cmd"] or ""
    cmd_id = row["id"]
    status = _status_str(ec)
    fs = ""
    try:
        findings_summary = row["findings_summary"]
        if findings_summary:
            fs = f"  → {findings_summary}"
    except (IndexError, KeyError):
        pass
    return f"[{cmd_id}] $ {cmd} [{status}]{fs}"


def _confirm_send(prompt: str, n_entries: int, total: int,
                  mode_label: str, ctx_window: int | None) -> bool:
    """Print token estimate + context fit, ask Continue? [y/n], return True if confirmed."""
    import math as _math
    est_tokens = len(prompt) // 4

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


# ── HTML rendering ────────────────────────────────────────────────────────────
#
# All modes generate Markdown (models produce it more reliably than HTML, and it
# costs fewer tokens). When --format html is requested, the final Markdown report
# is converted to a styled HTML document here, AFTER PSEVIDENCE injection — so the
# fenced evidence blocks render through the same converter.

_HTML_STYLE = """
  body { font-family: Arial, sans-serif; max-width: 960px; margin: 40px auto;
         color: #222; line-height: 1.5; padding: 0 16px; }
  h1 { color: #c0392b; }
  h2 { color: #2c3e50; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; }
  h3 { color: #34495e; }
  code { background: #eee; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; overflow-x: auto; }
  pre code { background: none; padding: 0; color: inherit; }
  blockquote { border-left: 4px solid #e74c3c; margin: 8px 0; padding: 4px 12px; background: #f9f9f9; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background: #f2f2f2; }
  hr { border: none; border-top: 1px solid #ddd; margin: 24px 0; }
  footer { color: #999; font-size: 0.85em; margin-top: 40px; }
"""


def _md_to_html(md_text: str, doc_title: str) -> str:
    """Convert a finished Markdown report to a styled, standalone HTML document."""
    import html as _h
    try:
        import markdown2
        body = markdown2.markdown(
            md_text,
            extras=[
                "fenced-code-blocks",  # ``` evidence blocks
                "tables",
                "code-friendly",       # don't treat _ inside code as emphasis
                "cuddled-lists",
                "break-on-newline",    # single newlines → <br> (meta block, lists)
            ],
        )
    except Exception:
        # markdown2 unavailable or failed — keep the report readable as raw text
        body = f"<pre>{_h.escape(md_text)}</pre>"
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        f"<meta charset=\"UTF-8\">\n<title>{_h.escape(doc_title)}</title>\n"
        f"<style>{_HTML_STYLE}</style>\n</head>\n<body>\n{body}\n</body>\n</html>"
    )


def _save_report(report_md: str, fmt: str, title: str,
                 base_dir: str, now: datetime) -> str:
    """Convert to HTML when requested, then write the report. Returns the path."""
    text = _md_to_html(report_md, title) if fmt == "html" else report_md
    reports_dir = os.path.join(base_dir, "appmodules", "Cyb3rCollector", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename    = f"report_{now.strftime('%Y-%m-%d_%H-%M')}.{fmt}"
    report_path = os.path.join(reports_dir, filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(text)
    return report_path


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
        status = _status_str(ec)
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


_RE_CMD_ID = re.compile(r'^cmd:(\d+)$', re.IGNORECASE)


def _resolve_placeholders(text: str, snapshot: list[dict]) -> str:
    """Replace <!-- PSEVIDENCE: ... --> markers with real terminal evidence.

    Two resolution modes:
    - Direct: <!-- PSEVIDENCE: cmd:47 --> → exact lookup by command ID (100% accurate)
    - Token:  <!-- PSEVIDENCE: nmap 192.168.1.10 smb --> → token-scored search

    Each unique command row is injected at most once across the whole report
    (deduplication by row id) to prevent the same evidence block from
    appearing in every section.  Token search requires at least 2 matching
    tokens so that single-word queries do not pull in unrelated commands.
    """
    pattern         = re.compile(r'<!--\s*PSEVIDENCE:\s*(.*?)\s*-->', re.IGNORECASE | re.DOTALL)
    used_ids:set[int] = set()
    snapshot_by_id: dict[int, dict] = {r["id"]: r for r in snapshot}

    def _replace(m: re.Match) -> str:
        query = m.group(1).strip()

        # Direct cmd:ID lookup (pomysł 3)
        id_match = _RE_CMD_ID.match(query)
        if id_match:
            row_id = int(id_match.group(1))
            row = snapshot_by_id.get(row_id)
            if row and row_id not in used_ids:
                used_ids.add(row_id)
                return "\n\n" + _format_evidence_block([row])
            # Already injected earlier (re.sub runs left-to-right, so the first
            # occurrence is always physically above). Leave a back-reference
            # instead of an empty string so a re-citation (e.g. in
            # Recommendations) keeps a visible pointer to its evidence.
            if row:
                return f"*(evidence for [cmd:{row_id}] shown above)*"
            return ""

        # Token-based search fallback
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
        f"Each command in [COMMANDS EXECUTED] is prefixed with its ID, e.g. [47].\n"
        f"Insert <!-- PSEVIDENCE: cmd:ID --> for exact evidence lookup (preferred),\n"
        f"or <!-- PSEVIDENCE: <search terms> --> for keyword-based lookup."
    )


# ── Minimal mode ──────────────────────────────────────────────────────────────

_MINI_TOOL_NAMES = [
    "nmap", "masscan", "rustscan", "gobuster", "feroxbuster", "dirb", "nikto",
    "wfuzz", "ffuf", "sqlmap", "nuclei", "wpscan", "droopescan",
    "enum4linux", "crackmapexec", "smbclient", "smbmap", "rpcclient", "ldapsearch",
    "bloodhound", "kerbrute", "secretsdump", "evil-winrm", "pwncat",
    "hydra", "medusa", "hashcat", "john", "credmaster",
    "msfconsole", "msfvenom", "searchsploit", "netcat", "socat",
    "chisel", "ligolo", "proxychains", "theHarvester", "amass", "subfinder",
    "aircrack", "wifite", "linpeas", "winpeas", "pspy", "impacket",
    "psexec", "wmiexec",
]

_MINI_SEVERITY_MAP = {
    "exploit": "Critical", "privesc": "Critical",
    "shell":   "High",     "lateral": "High",
    "crack":   "High",     "ad":      "High",
    "web":     "Medium",   "smb":     "Medium",
    "ldap":    "Medium",   "ssh":     "Medium",
    "ftp":     "Low",      "recon":   "Info",
    "scan":    "Info",
}

_MINI_OUT_LINES = 15
_MINI_OUT_CHARS = 400

# Timeline is an app-side display section (not an LLM prompt), and -L does not
# reach it — so cap it directly to keep the saved minimal report readable.
_MINI_TIMELINE_MAX  = 80   # max timeline entries rendered
_MINI_TIMELINE_HEAD = 15   # of those, keep this many from the start (recon opening)


def _mini_cap_output(text: str) -> str:
    if not text:
        return ""
    lines = text.strip().splitlines()[-_MINI_OUT_LINES:]
    out = "\n".join(lines)
    if len(out) > _MINI_OUT_CHARS:
        out = "...\n" + out[-_MINI_OUT_CHARS:].lstrip("\n")
    return out


def _mini_scope(conn: sqlite3.Connection, snapshot: list[dict]) -> str:
    all_phases = [
        "recon", "scan", "web", "smb", "ftp", "ssh", "ldap", "ad",
        "exploit", "privesc", "lateral", "crack", "shell",
        "network", "cloud", "forensics", "re", "wifi", "other",
    ]
    try:
        phase_rows = conn.execute(
            "SELECT ct.tag, COUNT(*) AS cnt FROM command_tags ct "
            "WHERE ct.tag IN ({}) GROUP BY ct.tag ORDER BY cnt DESC".format(
                ",".join("?" * len(all_phases))
            ),
            all_phases,
        ).fetchall()
    except Exception:
        phase_rows = []

    try:
        ts_row = conn.execute(
            "SELECT MIN(ts) AS t0, MAX(COALESCE(ts_end,ts)) AS t1 "
            "FROM commands WHERE ts IS NOT NULL"
        ).fetchone()
    except Exception:
        ts_row = None

    tools_used = []
    for tool in _MINI_TOOL_NAMES:
        for row in snapshot:
            if tool in (row.get("cmd") or "").lower():
                tools_used.append(tool)
                break

    try:
        host_count = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    except Exception:
        host_count = 0

    lines = []
    if ts_row and ts_row["t0"] and ts_row["t1"]:
        try:
            t0 = datetime.fromtimestamp(ts_row["t0"]).strftime("%Y-%m-%d %H:%M")
            t1 = datetime.fromtimestamp(ts_row["t1"]).strftime("%Y-%m-%d %H:%M")
            lines.append(f"- **Duration:** {t0} → {t1}")
        except Exception:
            pass
    if host_count:
        lines.append(f"- **Hosts discovered:** {host_count}")
    if phase_rows:
        ph = ", ".join(f"{r['tag']} ({r['cnt']})" for r in phase_rows)
        lines.append(f"- **Phases covered:** {ph}")
    if tools_used:
        lines.append(f"- **Tools used:** {', '.join(tools_used)}")
    return "\n".join(lines) if lines else "*No scope data available.*"


def _mini_assets(conn: sqlite3.Connection, target_filter: str | None) -> str:
    try:
        if target_filter:
            rows = conn.execute(
                """SELECT t.ip, t.hostname, t.os_guess,
                          tp.port, tp.protocol, tp.service, tp.version
                   FROM targets t
                   LEFT JOIN target_ports tp ON tp.target_id = t.id
                   WHERE t.ip = ? OR t.hostname = ?
                   ORDER BY t.ip, tp.port""",
                (target_filter, target_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT t.ip, t.hostname, t.os_guess,
                          tp.port, tp.protocol, tp.service, tp.version
                   FROM targets t
                   LEFT JOIN target_ports tp ON tp.target_id = t.id
                   ORDER BY t.ip, tp.port"""
            ).fetchall()
    except Exception:
        return "*Targets table unavailable.*"

    if not rows:
        return "*No assets discovered.*"

    hosts: dict[str, dict] = {}
    for r in rows:
        ip = r["ip"]
        if ip not in hosts:
            hosts[ip] = {"hostname": r["hostname"], "os": r["os_guess"], "ports": []}
        if r["port"] is not None:
            hosts[ip]["ports"].append(r)

    lines = []
    for ip, info in hosts.items():
        meta = [x for x in (info["hostname"], info["os"]) if x]
        lines.append(f"**{ip}**" + (f" ({' · '.join(meta)})" if meta else ""))
        for p in info["ports"]:
            line = f"- {p['port']}/{p['protocol']}"
            if p["service"]:
                line += f"  {p['service']}"
            if p["version"]:
                line += f"  {p['version'][:60]}"
            lines.append(line)
        lines.append("")
    return "\n".join(lines).rstrip()


def _mini_vulns(conn: sqlite3.Connection, snapshot: list[dict],
                target_filter: str | None) -> str:
    parts = []
    snapshot_by_id = {r["id"]: r for r in snapshot}
    _tf_cond = "AND (f.target = ? OR f.target IS NULL)" if target_filter else ""
    _tf_arg  = (target_filter,) if target_filter else ()

    try:
        cves = conn.execute(
            f"SELECT f.value, f.target, f.command_id FROM findings f "
            f"WHERE f.finding_type='cve' {_tf_cond} GROUP BY f.value ORDER BY f.value",
            _tf_arg,
        ).fetchall()
    except Exception:
        cves = []

    for r in cves:
        block = [f"### {r['value']}"]
        if r["target"]:
            block.append(f"*Affected: {r['target']}*")
        cmd_id = r["command_id"]
        if cmd_id and cmd_id in snapshot_by_id:
            row = snapshot_by_id[cmd_id]
            block.append(f"*Source: [cmd:{row['id']}] `{(row['cmd'] or '')[:80]}`*")
            out = _mini_cap_output(row.get("output") or "")
            if out:
                block.append("```")
                block.append(out)
                block.append("```")
        parts.append("\n".join(block))

    exploit_phases = ["exploit", "privesc", "lateral", "shell", "crack", "ad", "web", "smb"]
    seen_ids: set = set()
    for row in snapshot:
        tags = {t.strip() for t in (row.get("tags") or "").split(",") if t.strip()}
        if not tags & set(exploit_phases):
            continue
        rid = row["id"]
        if rid in seen_ids:
            continue
        seen_ids.add(rid)
        phase    = next((p for p in exploit_phases if p in tags), "other")
        ec       = row.get("exit_code")
        failed   = ec not in (0, None)
        # A failed command is not evidence of a vulnerability — don't rate it
        # by phase. Downgrade to Info and label it as an attempt so the model
        # doesn't treat exit!=0 offensive commands as confirmed Critical/High.
        severity = "Info" if failed else _MINI_SEVERITY_MAP.get(phase, "Info")
        label    = f"Attempted {phase.capitalize()}" if failed else phase.capitalize()
        cmd_short = (row.get("cmd") or "")[:80]
        status   = _status_str(ec)
        block  = [f"### [{severity}] {label} — [cmd:{rid}]"]
        block.append(f"`{cmd_short}` [{status}]")
        out = _mini_cap_output(row.get("output") or "")
        if out:
            block.append("```")
            block.append(out)
            block.append("```")
        parts.append("\n".join(block))
        if len(parts) >= 25:
            break

    return "\n\n".join(parts) if parts else "*No vulnerabilities identified.*"


def _mini_creds(conn: sqlite3.Connection, target_filter: str | None,
                snapshot: list[dict]) -> str:
    _tf_cond = "AND (f.target = ? OR f.target IS NULL)" if target_filter else ""
    _tf_arg  = (target_filter,) if target_filter else ()
    try:
        rows = conn.execute(
            f"SELECT f.finding_type, f.value, f.target, f.service, f.command_id "
            f"FROM findings f "
            f"WHERE f.finding_type IN ('credential','hash','user','flag') {_tf_cond} "
            f"ORDER BY f.finding_type, f.target, f.value",
            _tf_arg,
        ).fetchall()
    except Exception:
        return "*Findings table unavailable.*"

    if not rows:
        return "*No credentials or sensitive data found.*"

    snapshot_by_id = {r["id"]: r for r in snapshot}
    type_labels = {
        "credential": "Credentials",
        "hash":       "Password Hashes",
        "user":       "Discovered Users",
        "flag":       "Captured Flags",
    }
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(r["finding_type"], []).append(r)

    parts = []
    for ftype in ("credential", "hash", "user", "flag"):
        if ftype not in groups:
            continue
        lines = [f"**{type_labels[ftype]}**"]
        for r in groups[ftype]:
            val  = (r["value"] or "")
            meta = [x for x in (r["target"], r["service"]) if x]
            line = f"- `{val}`"
            if meta:
                line += f"  ({', '.join(meta)})"
            cmd_id = r["command_id"]
            if cmd_id and cmd_id in snapshot_by_id:
                row = snapshot_by_id[cmd_id]
                cmd_short = (row.get("cmd") or "")[:60]
                out = _mini_cap_output(row.get("output") or "")
                line += f"\n  *from: [cmd:{cmd_id}] `{cmd_short}`*"
                if out:
                    line += f"\n  ```\n{out}\n  ```"
            lines.append(line)
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def _mini_timeline(snapshot: list[dict]) -> str:
    if not snapshot:
        return "*No timeline data available.*"

    def _fmt(row: dict) -> str:
        ts  = row.get("ts")
        ts_str = ""
        if ts:
            try:
                ts_str = datetime.fromtimestamp(ts).strftime("%H:%M")
            except Exception:
                pass
        cmd    = (row.get("cmd") or "")[:100]
        ec     = row.get("exit_code")
        status = _status_str(ec)
        tags   = row.get("tags") or ""
        tag_str = f" [{tags}]" if tags else ""
        prefix  = f"`[{ts_str}]`" if ts_str else "-"
        return f"{prefix} `{cmd}` [{status}]{tag_str}"

    # Long engagement: keep the opening (recon) + the most recent actions so the
    # saved report stays readable. The snapshot itself is untouched — evidence
    # injection still resolves every cmd:ID.
    if len(snapshot) > _MINI_TIMELINE_MAX:
        tail_n  = _MINI_TIMELINE_MAX - _MINI_TIMELINE_HEAD
        omitted = len(snapshot) - _MINI_TIMELINE_HEAD - tail_n
        lines   = [_fmt(r) for r in snapshot[:_MINI_TIMELINE_HEAD]]
        lines.append(f"\n*… {omitted} earlier entries omitted ({len(snapshot)} total) …*\n")
        lines  += [_fmt(r) for r in snapshot[-tail_n:]]
    else:
        lines = [_fmt(r) for r in snapshot]
    return "\n".join(lines)


def _mini_exec_prompt(conn: sqlite3.Connection, snapshot: list[dict],
                      target_filter: str | None, sys_info: str,
                      now, ctx_k: int) -> str:
    surface_cap  = ctx_k * 300
    findings_cap = ctx_k * 200
    scope_cap    = ctx_k * 100

    try:
        if target_filter:
            rows = conn.execute(
                """SELECT t.ip, t.hostname, t.os_guess, tp.port, tp.protocol, tp.service
                   FROM targets t LEFT JOIN target_ports tp ON tp.target_id = t.id
                   WHERE t.ip = ? OR t.hostname = ? ORDER BY t.ip, tp.port""",
                (target_filter, target_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT t.ip, t.hostname, t.os_guess, tp.port, tp.protocol, tp.service
                   FROM targets t LEFT JOIN target_ports tp ON tp.target_id = t.id
                   ORDER BY t.ip, tp.port"""
            ).fetchall()
    except Exception:
        rows = []

    hosts: dict[str, dict] = {}
    for r in rows:
        ip = r["ip"]
        if ip not in hosts:
            hosts[ip] = {"hostname": r["hostname"], "os": r["os_guess"], "ports": []}
        if r["port"]:
            hosts[ip]["ports"].append(r)

    surface_lines = []
    for ip, info in hosts.items():
        meta = [x for x in (info["hostname"], info["os"]) if x]
        hdr  = ip + (f" ({' · '.join(meta)})" if meta else "")
        pts  = ", ".join(
            f"{p['port']}/{p['protocol']}" + (f" {p['service']}" if p["service"] else "")
            for p in info["ports"][:8]
        )
        surface_lines.append(f"{hdr}: {pts}" if pts else hdr)
    surface_text = "\n".join(surface_lines)
    if len(surface_text) > surface_cap:
        surface_text = surface_text[:surface_cap] + "\n..."

    _tf_cond = "AND (f.target = ? OR f.target IS NULL)" if target_filter else ""
    _tf_arg  = (target_filter,) if target_filter else ()

    findings_lines = []
    try:
        cve_rows = conn.execute(
            f"SELECT f.value FROM findings f WHERE f.finding_type='cve' {_tf_cond} "
            f"GROUP BY f.value ORDER BY f.value",
            _tf_arg,
        ).fetchall()
        if cve_rows:
            findings_lines.append("CVEs: " + ", ".join(r["value"] for r in cve_rows[:10]))
    except Exception:
        pass
    for ftype, label in (
        ("credential", "Credentials captured"),
        ("hash",       "Hashes captured"),
        ("user",       "Users discovered"),
        ("flag",       "Flags captured"),
    ):
        try:
            n = conn.execute(
                f"SELECT COUNT(DISTINCT f.value) FROM findings f "
                f"WHERE f.finding_type=? {_tf_cond}",
                (ftype,) + _tf_arg,
            ).fetchone()[0]
            if n:
                findings_lines.append(f"{label}: {n}")
        except Exception:
            pass
    try:
        exploit_n = conn.execute(
            "SELECT COUNT(DISTINCT c.id) FROM commands c "
            "JOIN command_tags ct ON ct.command_id = c.id "
            "WHERE ct.tag IN ('exploit','privesc','lateral','shell')"
        ).fetchone()[0]
        if exploit_n:
            findings_lines.append(f"Exploitation activities: {exploit_n} commands")
    except Exception:
        pass
    findings_text = "\n".join(findings_lines)
    if len(findings_text) > findings_cap:
        findings_text = findings_text[:findings_cap] + "\n..."

    all_phases = [
        "recon", "scan", "web", "smb", "ftp", "ssh", "ldap", "ad",
        "exploit", "privesc", "lateral", "crack", "shell",
        "network", "cloud", "forensics", "re", "wifi",
    ]
    scope_lines = []
    try:
        phase_rows = conn.execute(
            "SELECT ct.tag, COUNT(*) AS cnt FROM command_tags ct "
            "WHERE ct.tag IN ({}) GROUP BY ct.tag ORDER BY cnt DESC".format(
                ",".join("?" * len(all_phases))
            ),
            all_phases,
        ).fetchall()
        if phase_rows:
            scope_lines.append("Phases: " + ", ".join(f"{r['tag']}({r['cnt']})" for r in phase_rows))
    except Exception:
        pass
    try:
        ts_row = conn.execute(
            "SELECT MIN(ts) AS t0, MAX(COALESCE(ts_end,ts)) AS t1 "
            "FROM commands WHERE ts IS NOT NULL"
        ).fetchone()
        if ts_row and ts_row["t0"] and ts_row["t1"]:
            t0 = datetime.fromtimestamp(ts_row["t0"]).strftime("%Y-%m-%d %H:%M")
            t1 = datetime.fromtimestamp(ts_row["t1"]).strftime("%Y-%m-%d %H:%M")
            scope_lines.append(f"Duration: {t0} → {t1}")
    except Exception:
        pass
    if hosts:
        scope_lines.append(f"Hosts: {len(hosts)}")
    scope_text = "\n".join(scope_lines)
    if len(scope_text) > scope_cap:
        scope_text = scope_text[:scope_cap] + "\n..."

    prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d')}\n"
    prompt += f"Target: {target_filter or 'Unknown'}\n\n"
    if scope_text:
        prompt += f"[SCOPE]\n{scope_text}\n\n"
    if surface_text:
        prompt += f"[ATTACK SURFACE]\n{surface_text}\n\n"
    if findings_text:
        prompt += f"[KEY FINDINGS]\n{findings_text}\n\n"
    prompt += (
        "[TASK]\n"
        "Write a 2-3 paragraph Executive Summary covering:\n"
        "(1) what was tested and scope,\n"
        "(2) key findings and their impact,\n"
        "(3) overall risk posture and immediate priorities.\n"
        "Be concise. Output only the summary text, no section headers."
    )
    return prompt


def _mini_recs_prompt(conn: sqlite3.Connection, snapshot: list[dict],
                      target_filter: str | None, sys_info: str,
                      ctx_k: int) -> str:
    vulns_cap = ctx_k * 600
    creds_cap = ctx_k * 200

    _tf_cond = "AND (f.target = ? OR f.target IS NULL)" if target_filter else ""
    _tf_arg  = (target_filter,) if target_filter else ()

    vuln_lines = []
    try:
        cve_rows = conn.execute(
            f"SELECT f.value, f.target, f.service FROM findings f "
            f"WHERE f.finding_type='cve' {_tf_cond} GROUP BY f.value ORDER BY f.value",
            _tf_arg,
        ).fetchall()
        if cve_rows:
            vuln_lines.append("KNOWN CVEs:")
            for r in cve_rows:
                line = f"  - {r['value']}"
                meta = [x for x in (r["target"], r["service"]) if x]
                if meta:
                    line += f" ({', '.join(meta)})"
                vuln_lines.append(line)
    except Exception:
        pass

    exploit_phases = ["exploit", "privesc", "lateral", "shell", "crack", "ad", "web", "smb"]
    seen_phases: set[str] = set()
    for row in snapshot:
        tags  = {t.strip() for t in (row.get("tags") or "").split(",") if t.strip()}
        phase = next((p for p in exploit_phases if p in tags), None)
        if not phase or phase in seen_phases:
            continue
        seen_phases.add(phase)
        severity  = _MINI_SEVERITY_MAP.get(phase, "Info")
        cmd_short = (row.get("cmd") or "")[:80]
        ec        = row.get("exit_code")
        status    = _status_str(ec)
        vuln_lines.append(f"\n{severity.upper()} — {phase.capitalize()} phase:")
        vuln_lines.append(f"  Evidence: $ {cmd_short} [{status}]")
        out = _mini_cap_output(row.get("output") or "")
        if out:
            first = "\n".join(l for l in out.splitlines() if l.strip())[:200]
            if first:
                vuln_lines.append(f"  Output: {first}")

    vulns_text = "\n".join(vuln_lines)
    if len(vulns_text) > vulns_cap:
        vulns_text = vulns_text[:vulns_cap] + "\n..."

    creds_lines = []
    try:
        cred_rows = conn.execute(
            f"SELECT f.finding_type, f.value, f.target, f.service FROM findings f "
            f"WHERE f.finding_type IN ('credential','hash') {_tf_cond} "
            f"GROUP BY f.value ORDER BY f.finding_type, f.value",
            _tf_arg,
        ).fetchall()
        for r in cred_rows[:15]:
            line = f"  - [{r['finding_type']}] {(r['value'] or '')[:60]}"
            meta = [x for x in (r["target"], r["service"]) if x]
            if meta:
                line += f" ({', '.join(meta)})"
            creds_lines.append(line)
    except Exception:
        pass
    creds_text = "\n".join(creds_lines)
    if len(creds_text) > creds_cap:
        creds_text = creds_text[:creds_cap] + "\n..."

    prompt = f"System: {sys_info}\n\n"
    if vulns_text:
        prompt += f"[VULNERABILITIES & EVIDENCE]\n{vulns_text}\n\n"
    if creds_text:
        prompt += f"[CREDENTIALS FOUND — for context]\n{creds_text}\n\n"
    prompt += (
        "[TASK]\n"
        "Write concrete, actionable Recommendations for each vulnerability.\n"
        "Order: Critical → High → Medium → Low.\n"
        "For each: name, risk explanation, specific remediation steps (2-4 bullet points).\n"
        "Output only the recommendations section content, no report title or preamble."
    )
    return prompt


def _assemble_minimal_md(sections: dict[str, str], title: str,
                          target: str | None, now) -> str:
    ordered = [
        ("executive_summary", "Executive Summary"),
        ("scope",             "Scope & Methodology"),
        ("assets",            "Discovered Assets"),
        ("vulnerabilities",   "Vulnerabilities & Findings"),
        ("credentials",       "Credentials & Sensitive Data"),
        ("timeline",          "Timeline of Key Actions"),
        ("recommendations",   "Recommendations"),
    ]
    lines = [
        f"# {title}",
        f"**Date:** {now.strftime('%Y-%m-%d')}",
        f"**Target:** {target or 'Unknown'}",
        "**Tester:** [to be filled]",
        "**Status:** Draft — requires review",
        "", "---", "",
    ]
    for key, header in ordered:
        content = sections.get(key, "").strip()
        lines.append(f"## {header}")
        lines.append(content if content else "[No data generated for this section]")
        lines.append("")
    lines.append("---")
    lines.append("*Report generated by psreport --minimal — verify and complete before delivery.*")
    return "\n".join(lines)


def _run_minimal(
    conn: sqlite3.Connection,
    snapshot: list[dict],
    target_filter: str | None,
    sys_info: str,
    now,
    target: str | None,
    llm_fn,
    title: str,
    ctx_k: int,
) -> str | None:
    sections: dict[str, str] = {}

    sys.stderr.write(f"\n  Minimal mode: 5 app-side + 2 LLM calls  [{ctx_k}K context]\n\n")
    sys.stderr.flush()

    sys.stderr.write("  [1/7] Scope & Methodology (app-side)... ")
    sys.stderr.flush()
    sections["scope"] = _mini_scope(conn, snapshot)
    sys.stderr.write("done\n")

    sys.stderr.write("  [2/7] Discovered Assets (app-side)... ")
    sys.stderr.flush()
    sections["assets"] = _mini_assets(conn, target_filter)
    sys.stderr.write("done\n")

    sys.stderr.write("  [3/7] Vulnerabilities & Findings (app-side)... ")
    sys.stderr.flush()
    sections["vulnerabilities"] = _mini_vulns(conn, snapshot, target_filter)
    sys.stderr.write("done\n")

    sys.stderr.write("  [4/7] Credentials & Sensitive Data (app-side)... ")
    sys.stderr.flush()
    sections["credentials"] = _mini_creds(conn, target_filter, snapshot)
    sys.stderr.write("done\n")

    sys.stderr.write("  [5/7] Timeline (app-side)... ")
    sys.stderr.flush()
    sections["timeline"] = _mini_timeline(snapshot)
    sys.stderr.write("done\n")

    sys.stderr.write("  [6/7] Executive Summary (LLM)... ")
    sys.stderr.flush()
    p1      = _mini_exec_prompt(conn, snapshot, target_filter, sys_info, now, ctx_k)
    result1 = llm_fn([{"role": "user", "content": p1}], verbose=False)
    sections["executive_summary"] = (result1 or "").strip()
    sys.stderr.write(f"done  ({len((result1 or '').split())} words)\n")

    sys.stderr.write("  [7/7] Recommendations (LLM)... ")
    sys.stderr.flush()
    p2      = _mini_recs_prompt(conn, snapshot, target_filter, sys_info, ctx_k)
    result2 = llm_fn([{"role": "user", "content": p2}], verbose=False)
    sections["recommendations"] = (result2 or "").strip()
    sys.stderr.write(f"done  ({len((result2 or '').split())} words)\n")

    sys.stderr.write("\n  Assembling report...\n")
    sys.stderr.flush()

    # Always Markdown; main() converts to HTML via markdown2 when --format html.
    return _assemble_minimal_md(sections, title, target, now)


# ── Deep mode ─────────────────────────────────────────────────────────────────
#
# 3-pass generator–critic pipeline for top-tier, large-context models:
#   Pass 1  Investigation — read ALL commands WITH raw output, produce a
#           structured findings ledger (the curated evidence base).
#   Pass 2  Draft         — write the full report from the ledger (lean: the
#           ledger carries cmd:IDs, raw output is injected app-side afterward).
#   Pass 3  Critique       — senior self-review against the ledger, fix gaps /
#           unsupported claims / severity mismatches, emit the final report.
#
# Unlike the removed --chunked mode (same task on phase slices), each pass is a
# distinct cognitive mode over the WHOLE dataset, so the model keeps cross-phase
# correlation and uses the full window. Phase batching is only a fallback in
# Pass 1 when even a large window would overflow.

_DEEP_OUT_LINES = 4      # output lines per command,  multiplied by ctx_k
_DEEP_OUT_CHARS = 150    # output chars per command,  multiplied by ctx_k


def _deep_cap_output(text: str, max_lines: int, max_chars: int) -> str:
    """Cap a command's output, keeping the TAIL (results usually land last)."""
    if not text:
        return ""
    lines = text.strip().splitlines()
    truncated = False
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
        truncated = True
    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[-max_chars:]
        truncated = True
    if truncated:
        out = "...(truncated)...\n" + out.lstrip("\n")
    return out


def _deep_format_cmd(row, max_lines: int, max_chars: int) -> str:
    """Format one command as '[id] $ cmd [status] [tags]' + fenced output."""
    cmd_id = row["id"]
    cmd    = row["cmd"] or ""
    ec     = row["exit_code"]
    status = _status_str(ec)
    tags   = ""
    try:
        t = row["tags"]
        if t:
            tags = f"  [{t}]"
    except (IndexError, KeyError):
        pass
    block = f"[{cmd_id}] $ {cmd} [{status}]{tags}"
    try:
        out = _deep_cap_output(row["output"] or "", max_lines, max_chars)
    except (IndexError, KeyError):
        out = ""
    if out:
        block += "\n```\n" + out + "\n```"
    return block


def _deep_commands_block(entries, max_lines: int, max_chars: int) -> str:
    return "\n\n".join(_deep_format_cmd(e, max_lines, max_chars) for e in entries)


def _deep_group_by_phase(entries) -> list[tuple[str, list]]:
    """Group entries by primary phase tag (Pass-1 overflow fallback)."""
    buckets: dict[str, list] = {}
    for e in entries:
        tags    = [t.strip() for t in (e["tags"] or "").split(",") if t.strip()]
        primary = next((p for p in _PHASES_ORDER if p in tags), "other")
        buckets.setdefault(primary, []).append(e)
    return [(p, buckets[p]) for p in _PHASES_ORDER if p in buckets]


def _build_investigation_prompt(intel_header: str, commands_block: str,
                                sys_info: str, now, target: str | None) -> str:
    prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
    prompt += f"Target: {target or 'Unknown'}\n\n"
    if intel_header:
        prompt += f"{intel_header}\n\n"
    prompt += f"[COMMANDS WITH OUTPUT]\n{commands_block}\n\n"
    prompt += """[TASK]
You are the lead penetration tester analyzing a completed engagement.
Do NOT write the report yet. First investigate the raw terminal output above and
produce a structured FINDINGS LEDGER in Markdown. Read every output carefully and
extract concrete, evidence-backed facts.

Produce these sections (omit one only if genuinely empty):

## Hosts & Services
Each host: IP, hostname, OS, open ports with service/version. Cite [cmd:ID].

## Vulnerabilities
Each: name, severity (Critical/High/Medium/Low/Info), affected host, concrete
evidence quoted from the output, and [cmd:ID]. Justify every severity.

## Credentials & Secrets
Every credential, hash, key, token, and flag — exact value, source host, [cmd:ID].

## Attack Chains & Pivots
Trace how access was gained and escalated across hosts. Reference the [cmd:ID] of
each pivotal step. Correlate findings across phases.

## Gaps & Anomalies
Failed commands, partial results, or areas that look unfinished.

Quote exact values (hashes, versions, usernames) — never paraphrase them. Use the
bracketed [cmd:ID] shown before each command. Be exhaustive and precise: this
ledger is the sole evidence base for the report, so miss nothing."""
    return prompt


def _build_draft_prompt(intel_header: str, ledger: str, sys_info: str, now,
                        target: str | None, fmt_name: str, template: str) -> str:
    prompt  = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
    prompt += f"Target: {target or 'Unknown'}\n\n"
    if intel_header:
        prompt += f"{intel_header}\n\n"
    prompt += f"[FINDINGS LEDGER — your curated evidence base]\n{ledger}\n\n"
    prompt += f"""[TASK]
You are an expert penetration tester writing a professional report.
The findings ledger above is your authoritative, pre-analyzed evidence base —
every fact in the report must trace back to it. Do not invent findings.

For every specific finding, exploitation step, or discovered asset, insert a
placeholder marker on its own line immediately after the relevant sentence:

PREFERRED — direct ID reference (use the [cmd:ID] values from the ledger):
    <!-- PSEVIDENCE: cmd:47 -->

FALLBACK — keyword search (only when no command ID applies):
    <!-- PSEVIDENCE: <specific search terms> -->

The application replaces these markers with the real terminal command and output.
Aim for 1–3 markers per major finding. Severities must match the ledger.

Generate the complete {fmt_name} report below using exactly this template:

{template}"""
    return prompt


def _build_critique_prompt(intel_header: str, ledger: str, draft: str,
                           sys_info: str, fmt_name: str) -> str:
    prompt  = f"System: {sys_info}\n\n"
    if intel_header:
        prompt += f"{intel_header}\n\n"
    prompt += f"[FINDINGS LEDGER — ground truth]\n{ledger}\n\n"
    prompt += f"[DRAFT REPORT]\n{draft}\n\n"
    prompt += f"""[TASK]
You are a senior reviewer performing QA on the draft report against the ledger.
Critically check and FIX every issue, then output the improved final report only.

Checklist:
1. Coverage — every vulnerability, credential, and host in the ledger appears in
   the report. Add anything missing.
2. Support — every claim traces to ledger evidence. Remove or correct unsupported
   or invented statements.
3. Severity — ratings match the ledger and are justified.
4. Consistency — the Executive Summary matches the body; no contradictions.
5. Recommendations — each maps to a specific finding, ordered by severity.
6. Evidence markers — keep and repair <!-- PSEVIDENCE: cmd:ID --> placeholders and
   add them where strong findings lack one. Do NOT expand the markers yourself.
7. Professional tone and correct {fmt_name} structure following the template.

Output ONLY the final, corrected {fmt_name} report — no commentary, no diff, and
no preamble describing what you changed."""
    return prompt


def _run_deep(
    entries,
    intel_header: str,
    sys_info: str,
    now,
    target: str | None,
    fmt_name: str,
    template: str,
    llm_fn,
    ctx_k: int,
    ctx_window: int | None,
    verbose: bool,
) -> str | None:
    """3-pass deep generation. Returns the final report text (pre-injection)."""
    max_lines = max(20,  ctx_k * _DEEP_OUT_LINES)
    max_chars = max(800, ctx_k * _DEEP_OUT_CHARS)

    sys.stderr.write(
        f"\n  Deep mode: 3-pass (investigate → draft → critique)  [{ctx_k}K context]\n\n"
    )
    sys.stderr.flush()

    # ── Pass 1: Investigation (overflow → phase-batched ledger merge) ──────────
    sys.stderr.write("  [1/3] Investigation — analyzing raw output... ")
    sys.stderr.flush()

    full_block = _deep_commands_block(entries, max_lines, max_chars)
    est_tokens = len(full_block) // 4
    budget     = int((ctx_window or 0) * 0.6)

    if ctx_window and est_tokens > budget and len(entries) > 1:
        groups = _deep_group_by_phase(entries)
        sys.stderr.write(f"\n        large dataset → {len(groups)} phase batch(es)\n")
        sys.stderr.flush()
        ledgers = []
        for i, (phase, grp) in enumerate(groups, 1):
            sys.stderr.write(f"        [{i}/{len(groups)}] {phase} ({len(grp)} cmds)... ")
            sys.stderr.flush()
            block = _deep_commands_block(grp, max_lines, max_chars)
            p     = _build_investigation_prompt(intel_header, block, sys_info, now, target)
            part  = llm_fn([{"role": "user", "content": p}], verbose=False)
            ledgers.append(f"### Phase: {phase}\n{(part or '').strip()}")
            sys.stderr.write("done\n")
            sys.stderr.flush()
        ledger = "\n\n".join(ledgers)
        sys.stderr.write("        ledgers merged\n")
        sys.stderr.flush()
    else:
        p      = _build_investigation_prompt(intel_header, full_block, sys_info, now, target)
        ledger = (llm_fn([{"role": "user", "content": p}], verbose=False) or "").strip()
        sys.stderr.write(f"done  ({len(ledger.split())} words)\n")
        sys.stderr.flush()

    if not ledger:
        return None

    # ── Pass 2: Draft ──────────────────────────────────────────────────────────
    sys.stderr.write("  [2/3] Drafting report from ledger... ")
    sys.stderr.flush()
    p2    = _build_draft_prompt(intel_header, ledger, sys_info, now, target, fmt_name, template)
    # Pass 2 is the product — it cannot be skipped. A batched ledger from a long
    # engagement can still swell it past the window, so at least warn instead of
    # letting the model silently truncate/refuse the draft.
    if ctx_window and len(p2) // 4 > budget:
        sys.stderr.write(
            f"\n        \033[33mwarning: draft prompt ~{len(p2) // 4:,} tokens exceeds "
            f"{budget:,}-token budget — report may be truncated by the model\033[0m\n        "
        )
        sys.stderr.flush()
    draft = (llm_fn([{"role": "user", "content": p2}], verbose=False) or "").strip()
    sys.stderr.write(f"done  ({len(draft.split())} words)\n")
    sys.stderr.flush()
    if not draft:
        return None

    # ── Pass 3: Critique & finalize ────────────────────────────────────────────
    p3 = _build_critique_prompt(intel_header, ledger, draft, sys_info, fmt_name)
    # Critique is a refinement, not the product — the draft is already a complete
    # report. If Pass 3 would overflow the window, skip it and return the draft
    # as-is rather than risk a silent truncation/refusal.
    if ctx_window and len(p3) // 4 > budget:
        sys.stderr.write(
            f"  [3/3] Critique skipped — prompt ~{len(p3) // 4:,} tokens exceeds "
            f"{budget:,}-token budget; returning uncritiqued draft.\n"
        )
        sys.stderr.flush()
        return draft
    sys.stderr.write("  [3/3] Critique & finalize...")
    sys.stderr.write("\n" if verbose else " ")
    sys.stderr.flush()
    final = (llm_fn([{"role": "user", "content": p3}], verbose=verbose) or "").strip()
    sys.stderr.write(f"done  ({len(final.split())} words)\n")
    sys.stderr.flush()

    # Critique returning empty → fall back to the draft rather than failing.
    return final or draft


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psreport", add_help=False)
    parser.add_argument("-t", "--target",  default=None, metavar="TARGET")
    parser.add_argument("-T", "--title",   default=None, metavar="TITLE")
    parser.add_argument("-L", "--limit",   default=None, type=int, metavar="N",
                        help="Keep last N commands per phase category (recon/scan/exploit/…); "
                             "applies to the default and --deep modes (which send the command "
                             "list to the model) — balances coverage across the whole engagement")
    parser.add_argument("-m", "--minimal", nargs="?", const=-1, default=None, type=int,
                        metavar="K",
                        help="Minimal mode: 5 app-side sections + 2 LLM calls only "
                             "(exec summary + recommendations); suited for small models; "
                             "K = context in K tokens (e.g. -m 4); auto from profile if omitted (-m)")
    parser.add_argument("-d", "--deep", nargs="?", const=-1, default=None, type=int,
                        metavar="K",
                        help="Deep mode: 3-pass generation (investigate → draft → critique) "
                             "with full command output; for top-tier large-context models; "
                             "K = context in K tokens (e.g. -d 64); auto from profile if omitted (-d)")
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
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psreport — AI-powered pentest report generator\n\n"
            "Usage:\n"
            "  psreport                                    Generate report from full filtered history\n"
            "  psreport -L, --limit N                      Last N commands per phase (recon/scan/exploit/…) — balanced coverage (default & --deep)\n"
            "  psreport -m [K], --minimal [K]              Minimal: app-side report + 2 LLM calls (exec summary + recommendations); K = context K tokens; for small models\n"
            "  psreport -d [K], --deep [K]                 Deep: 3-pass (investigate → draft → critique) with full output; K = context K tokens; for top-tier models\n"
            "  psreport -n, --notes notes.txt              Notes mode: report from your notes + terminal evidence\n"
            "  psreport -v, --verbose                      Stream synthesis to terminal while saving\n"
            "  psreport -f, --format html                  Generate HTML report instead of Markdown\n"
            "  psreport -t, --target 192.168.1.10          Filter attack surface to a specific host/IP\n"
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

    # Modes are mutually exclusive — dispatch picks the first that matches
    # (notes > minimal > deep > standard), so passing more than one would
    # silently ignore the rest. Fail fast instead of guessing intent.
    _modes = [n for n, v in (
        ("--notes",   args.notes),
        ("--minimal", args.minimal),
        ("--deep",    args.deep),
    ) if v is not None]
    if len(_modes) > 1:
        _ai._err(f"Modes are mutually exclusive — {', '.join(_modes)} given together. Pick one.")
        sys.exit(1)

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
    # The model always writes Markdown; HTML is rendered from it at save time
    # (markdown2) — models produce Markdown more reliably and it costs fewer tokens.
    fmt_name  = "Markdown"
    template  = _report_template_md(title, target or "Unknown", now)

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
immediately after the relevant sentence.

PREFERRED — direct ID reference using [ID] from the findings' source commands:
    <!-- PSEVIDENCE: cmd:47 -->

FALLBACK — keyword search when no specific command ID is known:
    <!-- PSEVIDENCE: <specific search terms> -->

The application will replace these markers with the actual terminal command
and its output from the session database, including timestamp.
Use precise, specific terms — IP addresses, tool names, CVE IDs, service
names, port numbers, hash values, usernames.

Keyword examples:
    <!-- PSEVIDENCE: nmap 192.168.1.10 port 445 smb -->
    <!-- PSEVIDENCE: hydra brute force ssh admin password -->
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

        try:
            report_path = _save_report(resolved, fmt, title, base_dir, now)
            _ai._info(f"Report saved: {os.path.relpath(report_path, base_dir)}\n")
        except Exception as e:
            _ai._err(f"Failed to save report: {e}")
            sys.exit(1)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # MINIMAL MODE — app-side sections + 2 LLM calls (exec summary + recs)
    # ══════════════════════════════════════════════════════════════════════════
    if args.minimal is not None:
        if args.minimal == -1:
            ctx_window_m = _ai._get_ctx_window(profile, base_dir)
            ctx_k        = max(1, ctx_window_m // 1000) if ctx_window_m else 4
            ctx_source   = f"auto from profile ({ctx_k}K)"
        else:
            ctx_k        = args.minimal
            ctx_window_m = ctx_k * 1000
            ctx_source   = f"manual ({ctx_k}K)"

        conn_m = _db_connect(base_dir)
        if not conn_m:
            _ai._err("No terminal history database found.")
            sys.exit(1)

        try:
            snapshot_m = _snapshot_history(conn_m)
            total_m    = conn_m.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
        except Exception as _e:
            conn_m.close()
            _ai._err(f"Database error: {_e}")
            sys.exit(1)

        sys.stderr.write(
            f"\n  Entries  : {len(snapshot_m)}/{total_m} (relevant commands)\n"
            f"  Context  : {ctx_source} per LLM call\n"
            f"  API calls: 2 (exec summary + recommendations)\n"
            f"\nContinue? [y/n] "
        )
        sys.stderr.flush()
        try:
            _reply_m = sys.stdin.readline().strip()
        except Exception:
            _reply_m = ""
        if _reply_m.lower() != "y":
            conn_m.close()
            sys.stderr.write("Aborted.\n")
            sys.exit(0)

        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")

        try:
            response = _run_minimal(
                conn=conn_m,
                snapshot=snapshot_m,
                target_filter=target,
                sys_info=sys_info,
                now=now,
                target=target,
                llm_fn=_llm,
                title=title,
                ctx_k=ctx_k,
            )
        finally:
            conn_m.close()

        if not response:
            _ai._err("No response from model.")
            sys.exit(1)

        try:
            report_path = _save_report(response, fmt, title, base_dir, now)
            _ai._info(f"\nReport saved: {os.path.relpath(report_path, base_dir)}\n")
        except Exception as e:
            _ai._err(f"Failed to save report: {e}")
            sys.exit(1)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # DEEP MODE — 3-pass (investigate → draft → critique) for top-tier models
    # ══════════════════════════════════════════════════════════════════════════
    if args.deep is not None:
        if args.deep == -1:
            ctx_window_d = _ai._get_ctx_window(profile, base_dir)
            ctx_k        = max(1, ctx_window_d // 1000) if ctx_window_d else 32
            ctx_source   = f"auto from profile ({ctx_k}K)"
        else:
            ctx_k        = args.deep
            ctx_window_d = ctx_k * 1000
            ctx_source   = f"manual ({ctx_k}K)"

        entries_d, total_d = _load_entries_sqlite(base_dir, limit_per_phase=args.limit)
        if not entries_d and not intel_header:
            _ai._err("No relevant history found — run some pentest commands first.")
            sys.exit(1)

        conn_snap_d = _db_connect(base_dir)
        snapshot_d: list[dict] = []
        if conn_snap_d:
            try:
                snapshot_d = _snapshot_history(conn_snap_d)
            finally:
                conn_snap_d.close()

        sys.stderr.write(
            f"\n  Entries  : {len(entries_d)}/{total_d} (relevant commands, full output)\n"
            f"  Context  : {ctx_source} per pass\n"
            f"  API calls: 3 (investigation + draft + critique)\n"
            f"\n  Deep mode targets large, high-quality models (32K+ context).\n"
            f"\nContinue? [y/n] "
        )
        sys.stderr.flush()
        try:
            _reply_d = sys.stdin.readline().strip()
        except Exception:
            _reply_d = ""
        if _reply_d.lower() != "y":
            sys.stderr.write("Aborted.\n")
            sys.exit(0)

        if _ai._SHOW_QUERYING:
            _ai._info(f"Querying {model} via {provider}…\n")

        response = _run_deep(
            entries=entries_d,
            intel_header=intel_header,
            sys_info=sys_info,
            now=now,
            target=target,
            fmt_name=fmt_name,
            template=template,
            llm_fn=_llm,
            ctx_k=ctx_k,
            ctx_window=ctx_window_d,
            verbose=args.verbose,
        )
        if not response:
            _ai._err("No response from model.")
            sys.exit(1)

        _ai._info("Injecting terminal evidence...\n")
        resolved = _resolve_placeholders(response, snapshot_d)
        injected = response.count("<!-- PSEVIDENCE:") - resolved.count("<!-- PSEVIDENCE:")
        _ai._info(f"Evidence injected: {injected} placeholder(s) resolved.\n")

        try:
            report_path = _save_report(resolved, fmt, title, base_dir, now)
            _ai._info(f"\nReport saved: {os.path.relpath(report_path, base_dir)}\n")
        except Exception as e:
            _ai._err(f"Failed to save report: {e}")
            sys.exit(1)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # STANDARD MODE — intel header + commands (no output) + evidence injection
    # ══════════════════════════════════════════════════════════════════════════
    entries, total = _load_entries_sqlite(base_dir, limit_per_phase=args.limit)
    if not entries and not intel_header:
        _ai._err("No relevant history found — run some pentest commands first.")
        sys.exit(1)

    # Snapshot full history for placeholder resolution (done before confirm
    # so the snapshot is consistent with what the model sees)
    conn_snap = _db_connect(base_dir)
    snapshot: list[dict] = []
    if conn_snap:
        try:
            snapshot = _snapshot_history(conn_snap)
        finally:
            conn_snap.close()

    snap_summary = _build_snapshot_summary(snapshot)

    commands = "\n".join(_format_entry(e) for e in entries)
    prompt   = f"System: {sys_info}\nDate: {now.strftime('%Y-%m-%d %H:%M')}\n"
    prompt  += f"Target: {target or 'Unknown'}\n"
    if cwd:
        prompt  += f"Working directory: {cwd}\n"
    if intel_header:
        prompt  += f"\n{intel_header}\n"
    if commands:
        cmds_label = (f"last {args.limit}/phase → {len(entries)} total"
                      if args.limit else f"all {len(entries)} filtered")
        prompt  += f"\n[COMMANDS EXECUTED — {cmds_label}]\n{commands}\n"
    if snap_summary:
        prompt  += f"\n{snap_summary}\n"
    prompt += f"""
[INSTRUCTIONS]
You are an expert penetration tester writing a professional report.
The intelligence summary and command list above are your data sources.

For every specific finding, exploitation step, or discovered asset you write
about, insert a placeholder marker on its own line immediately after the
relevant sentence.

PREFERRED — direct ID reference (100% accurate, use the [ID] shown in the command list):
    <!-- PSEVIDENCE: cmd:47 -->

FALLBACK — keyword search (use when no specific command ID applies):
    <!-- PSEVIDENCE: <specific search terms> -->

The application will replace these markers with the actual terminal command
and its output from the session database, including timestamp.
When using keyword search, use precise terms — IP addresses, tool names,
CVE IDs, service names, port numbers, hash values, usernames.

Keyword examples:
    <!-- PSEVIDENCE: nmap 192.168.1.10 port 445 smb -->
    <!-- PSEVIDENCE: hydra brute force ssh admin password -->
    <!-- PSEVIDENCE: linpeas suid privesc root -->

Aim for 1–3 markers per major finding. Do not invent terminal outputs.
If something likely has no terminal evidence, omit the marker.
Mark sections as '[No data found]' if no evidence exists.
Do not invent findings.

Generate the complete {fmt_name} report below using exactly this template:

{template}"""

    mode_label = f"last {args.limit} per phase" if args.limit else "full filtered history"
    ctx_window_std = _ai._get_ctx_window(profile, base_dir)
    if not _confirm_send(prompt, len(entries), total, mode_label, ctx_window_std):
        sys.exit(0)

    # ── LLM call ──────────────────────────────────────────────────────────────
    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info("Generating report...\n")
    messages = [{"role": "user", "content": prompt}]
    response = _llm(messages, verbose=args.verbose)

    if not response:
        _ai._err("No response from model.")
        sys.exit(1)

    # ── Inject terminal evidence ───────────────────────────────────────────────
    _ai._info("Injecting terminal evidence...\n")
    resolved = _resolve_placeholders(response, snapshot)
    injected = response.count("<!-- PSEVIDENCE:") - resolved.count("<!-- PSEVIDENCE:")
    _ai._info(f"Evidence injected: {injected} placeholder(s) resolved.\n")

    # ── Save to file ──────────────────────────────────────────────────────────
    try:
        report_path = _save_report(resolved, fmt, title, base_dir, now)
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
