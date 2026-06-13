#!/usr/bin/env python3
"""
pshistory — query the PurrSh3ll terminal history SQLite database.

Usage:
  pshistory                    — show last 20 commands
  pshistory -n 50              — show last 50 commands
  pshistory -s                 — list sessions
  pshistory --session 3        — show commands in session 3
  pshistory -q nmap            — search commands/output for 'nmap'
  pshistory --findings         — show all findings
  pshistory --stats            — show DB stats
  pshistory --db /path/to/db   — use a custom DB path
"""

import argparse
import os
import sys
import sqlite3
from datetime import datetime

DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "terminal_history.db"
)


def _ts(unix):
    if unix is None:
        return "-"
    try:
        return datetime.fromtimestamp(int(unix)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(unix)


def _trunc(text, n=80):
    if not text:
        return ""
    text = text.replace("\n", " ")
    return text[:n] + "…" if len(text) > n else text


def _connect(db_path):
    if not os.path.exists(db_path):
        print(f"[pshistory] DB not found: {db_path}", file=sys.stderr)
        print("  Start PurrSh3ll and run a few commands first.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def cmd_list(conn, n, session_id):
    if session_id is not None:
        rows = conn.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
            (session_id, n)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM commands ORDER BY ts DESC LIMIT ?", (n,)
        ).fetchall()

    rows = list(reversed(rows))
    if not rows:
        print("No commands found.")
        return

    print(f"{'ID':>6}  {'TIME':19}  {'EXIT':>4}  {'TERMINAL':12}  COMMAND")
    print("-" * 100)
    for r in rows:
        ec = r['exit_code']
        ec_str = str(ec) if ec is not None else '?'
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {ec_str:>4}  "
              f"{(r['terminal'] or ''):12}  {_trunc(r['cmd'], 60)}")


def cmd_sessions(conn):
    rows = conn.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 50").fetchall()
    if not rows:
        print("No sessions found.")
        return

    print(f"{'ID':>4}  {'STARTED':19}  {'ENDED':19}  {'MODE':10}  {'TARGET':16}  LABEL")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>4}  {_ts(r['started_at']):19}  {_ts(r['ended_at']):19}  "
              f"{(r['mode'] or ''):10}  {(r['target_ip'] or ''):16}  {r['label'] or ''}")


def cmd_search(conn, pattern, n):
    like = f"%{pattern}%"
    rows = conn.execute(
        "SELECT * FROM commands WHERE cmd LIKE ? OR output LIKE ? ORDER BY ts DESC LIMIT ?",
        (like, like, n)
    ).fetchall()
    rows = list(reversed(rows))

    if not rows:
        print(f"No results for '{pattern}'.")
        return

    print(f"Found {len(rows)} result(s) for '{pattern}':\n")
    print(f"{'ID':>6}  {'TIME':19}  {'EXIT':>4}  COMMAND")
    print("-" * 100)
    for r in rows:
        ec = r['exit_code']
        ec_str = str(ec) if ec is not None else '?'
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {ec_str:>4}  "
              f"{_trunc(r['cmd'], 60)}")
        if r['output']:
            for line in (r['output'] or "").split("\n"):
                if pattern.lower() in line.lower():
                    print(f"{'':>6}  {'':19}        ↳ {_trunc(line, 70)}")


def cmd_findings(conn, session_id):
    if session_id is not None:
        rows = conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY ts DESC", (session_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY ts DESC LIMIT 200"
        ).fetchall()

    if not rows:
        print("No findings found.")
        return

    print(f"{'ID':>5}  {'TYPE':12}  {'TARGET':16}  {'PORT':>5}  VALUE")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>5}  {(r['finding_type'] or ''):12}  {(r['target'] or ''):16}  "
              f"{str(r['port'] or ''):>5}  {_trunc(r['value'], 50)}")


def cmd_stats(conn):
    n_cmd = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    n_ses = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    n_find = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    n_tags = conn.execute("SELECT COUNT(*) FROM command_tags").fetchone()[0]
    n_tgt = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    n_ports = conn.execute("SELECT COUNT(*) FROM target_ports").fetchone()[0]

    print("PurrSh3ll terminal history DB stats")
    print(f"  Commands : {n_cmd}")
    print(f"  Sessions : {n_ses}")
    print(f"  Findings : {n_find}")
    print(f"  Tags     : {n_tags}")
    print(f"  Targets  : {n_tgt}")
    print(f"  Ports    : {n_ports}")

    top_tags = conn.execute(
        "SELECT tag, COUNT(*) AS c FROM command_tags GROUP BY tag ORDER BY c DESC LIMIT 10"
    ).fetchall()
    if top_tags:
        print("\n  Top tags:")
        for r in top_tags:
            print(f"    {r['tag']:20} {r['c']}")

    exit_ok = conn.execute("SELECT COUNT(*) FROM commands WHERE exit_code = 0").fetchone()[0]
    exit_err = conn.execute("SELECT COUNT(*) FROM commands WHERE exit_code != 0 AND exit_code IS NOT NULL").fetchone()[0]
    print(f"\n  Exit 0   : {exit_ok}")
    print(f"  Exit !=0 : {exit_err}")


def cmd_show(conn, cmd_id):
    row = conn.execute("SELECT * FROM commands WHERE id = ?", (cmd_id,)).fetchone()
    if not row:
        print(f"Command id={cmd_id} not found.")
        return
    tags = [r["tag"] for r in conn.execute(
        "SELECT tag FROM command_tags WHERE command_id = ? ORDER BY tag", (cmd_id,)
    ).fetchall()]
    print(f"ID        : {row['id']}")
    print(f"Session   : {row['session_id']}")
    print(f"Terminal  : {row['terminal']}")
    print(f"Time      : {_ts(row['ts'])} → {_ts(row['ts_end'])}  ({row['duration_ms']} ms)")
    print(f"Exit code : {row['exit_code']}")
    print(f"CWD       : {row['cwd'] or '-'}")
    print(f"Tags      : {', '.join(tags) or '-'}")
    print(f"Command   :\n  {row['cmd']}")
    if row['output']:
        print(f"Output ({row['output_size']} bytes):\n{row['output']}")


def main():
    ap = argparse.ArgumentParser(description="Query PurrSh3ll terminal history DB")
    ap.add_argument("--db", default=DEFAULT_DB, help="Path to terminal_history.db")
    ap.add_argument("-n", type=int, default=20, help="Number of results (default 20)")
    ap.add_argument("-s", "--sessions", action="store_true", help="List sessions")
    ap.add_argument("--session", type=int, default=None, metavar="ID", help="Filter by session ID")
    ap.add_argument("-q", "--search", metavar="PATTERN", help="Search commands and output")
    ap.add_argument("--findings", action="store_true", help="Show findings")
    ap.add_argument("--stats", action="store_true", help="Show DB statistics")
    ap.add_argument("--show", type=int, metavar="ID", help="Show full details of a command by ID")
    args = ap.parse_args()

    conn = _connect(args.db)

    if args.sessions:
        cmd_sessions(conn)
    elif args.search:
        cmd_search(conn, args.search, args.n)
    elif args.findings:
        cmd_findings(conn, args.session)
    elif args.stats:
        cmd_stats(conn)
    elif args.show is not None:
        cmd_show(conn, args.show)
    else:
        cmd_list(conn, args.n, args.session)

    conn.close()


if __name__ == "__main__":
    main()
