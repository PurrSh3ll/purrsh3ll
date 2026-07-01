#!/usr/bin/env python3
"""
pshistory — query the PurrSh3ll terminal history SQLite database.

BROWSING
  pshistory                    show last 20 commands
  pshistory -n 50              show last 50 commands
  pshistory --all              show full history
  pshistory --show 42          show full output of command id=42

SEARCH & FILTER
  pshistory -q nmap            search commands/output for 'nmap'
  pshistory -t recon           show commands tagged as 'recon'
  pshistory -t recon -n 50     show last 50 recon commands
  pshistory -t exploit --all   show all exploitation commands
  pshistory --categories       list all categories (tag + label + DB count)

RECON DATA
  pshistory --targets          show all discovered targets (IPs / hostnames)
  pshistory --ports            show all open ports (all targets)
  pshistory --ports 10.10.10.1 show open ports for a specific target
  pshistory --findings         show all auto-extracted findings

MISC
  pshistory --stats            show DB statistics
  pshistory --clear            delete entire history (asks for confirmation)
  pshistory --clear -y         delete without confirmation
"""

import argparse
import os
import sys
import sqlite3
from datetime import datetime

DEFAULT_DB = (os.environ.get("PSDB")
              or os.path.join(
                  os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "logs", "terminal_history.db"
              ))


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


def _ec(row):
    ec = row['exit_code']
    return str(ec) if ec is not None else '?'


def _connect(db_path):
    if not os.path.exists(db_path):
        print(f"[pshistory] DB not found: {db_path}", file=sys.stderr)
        print("  Start PurrSh3ll and run a few commands first.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _print_commands(rows):
    print(f"{'ID':>6}  {'TIME':19}  {'EXIT':>4}  {'TERMINAL':12}  COMMAND")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {_ec(r):>4}  "
              f"{(r['terminal'] or ''):12}  {_trunc(r['cmd'], 60)}")


def cmd_list(conn, n):
    rows = conn.execute(
        "SELECT * FROM commands ORDER BY ts DESC LIMIT ?", (n,)
    ).fetchall()
    rows = list(reversed(rows))
    if not rows:
        print("No commands found.")
        return
    _print_commands(rows)


def cmd_all(conn):
    total = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    rows = conn.execute("SELECT * FROM commands ORDER BY ts ASC").fetchall()
    print(f"{'ID':>6}  {'TIME':19}  {'EXIT':>4}  {'TERMINAL':12}  COMMAND  ({total} total)")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {_ec(r):>4}  "
              f"{(r['terminal'] or ''):12}  {_trunc(r['cmd'], 60)}")


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
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {_ec(r):>4}  {_trunc(r['cmd'], 60)}")
        for line in (r['output'] or "").split("\n"):
            if pattern.lower() in line.lower():
                print(f"{'':>6}  {'':19}        ↳ {_trunc(line, 70)}")


def cmd_category(conn, cat, n, show_all):
    if show_all:
        rows = conn.execute(
            """
            SELECT c.* FROM commands c
            JOIN command_tags t ON t.command_id = c.id
            WHERE t.tag = ?
            ORDER BY c.ts ASC
            """,
            (cat,)
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT c.* FROM commands c
            JOIN command_tags t ON t.command_id = c.id
            WHERE t.tag = ?
            ORDER BY c.ts DESC LIMIT ?
            """,
            (cat, n)
        ).fetchall()
        rows = list(reversed(rows))
    if not rows:
        print(f"No commands tagged '{cat}'.")
        return
    print(f"{'ID':>6}  {'TIME':19}  {'EXIT':>4}  {'TERMINAL':12}  COMMAND  ({len(rows)} in '{cat}')")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>6}  {_ts(r['ts']):19}  {_ec(r):>4}  "
              f"{(r['terminal'] or ''):12}  {_trunc(r['cmd'], 60)}")


def cmd_categories(db_path):
    json_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tool_categories.json"
    )
    try:
        import json
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cats = data.get("categories", {})
    except Exception:
        print(f"[pshistory] Could not read tool_categories.json: {json_path}", file=sys.stderr)
        return

    # also get DB counts per tag if DB exists
    counts = {}
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT tag, COUNT(*) AS c FROM command_tags GROUP BY tag"
            ).fetchall()
            counts = {r["tag"]: r["c"] for r in rows}
            conn.close()
        except Exception:
            pass

    print(f"{'TAG':12}  {'LABEL':28}  IN DB")
    print("-" * 50)
    for key, label in cats.items():
        c = counts.get(key, 0)
        count_str = str(c) if c else "-"
        print(f"{key:12}  {label:28}  {count_str}")


def cmd_targets(conn):
    rows = conn.execute("SELECT * FROM targets ORDER BY ip").fetchall()
    if not rows:
        print("No targets found.")
        return
    print(f"{'ID':>4}  {'IP':16}  {'HOSTNAME':24}  {'OS':28}  NOTES")
    print("-" * 100)
    for r in rows:
        port_count = conn.execute(
            "SELECT COUNT(*) FROM target_ports WHERE target_id = ?", (r['id'],)
        ).fetchone()[0]
        notes = (r['notes'] or '')
        print(f"{r['id']:>4}  {(r['ip'] or ''):16}  {(r['hostname'] or ''):24}  "
              f"{(r['os_guess'] or ''):28}  {_trunc(notes, 20)}  [{port_count} port(s)]")


def cmd_ports(conn, ip=None):
    if ip:
        tgt = conn.execute("SELECT * FROM targets WHERE ip = ?", (ip,)).fetchone()
        if not tgt:
            print(f"Target '{ip}' not found.")
            return
        rows = conn.execute(
            "SELECT p.*, t.ip, t.hostname FROM target_ports p "
            "JOIN targets t ON t.id = p.target_id "
            "WHERE p.target_id = ? ORDER BY p.port",
            (tgt['id'],)
        ).fetchall()
        print(f"Ports for {ip}  ({tgt['hostname'] or '-'}):")
    else:
        rows = conn.execute(
            "SELECT p.*, t.ip, t.hostname FROM target_ports p "
            "JOIN targets t ON t.id = p.target_id "
            "ORDER BY t.ip, p.port"
        ).fetchall()
    if not rows:
        print("No ports found.")
        return
    print(f"{'IP':16}  {'PORT':>5}  {'PROTO':5}  {'STATE':8}  {'SERVICE':16}  VERSION")
    print("-" * 100)
    for r in rows:
        print(f"{(r['ip'] or ''):16}  {r['port']:>5}  {(r['protocol'] or ''):5}  "
              f"{(r['state'] or ''):8}  {(r['service'] or ''):16}  "
              f"{_trunc(r['version'] or '', 30)}")


def cmd_findings(conn):
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
    n_cmd  = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    n_find = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    n_tags = conn.execute("SELECT COUNT(*) FROM command_tags").fetchone()[0]
    n_tgt  = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    n_ports = conn.execute("SELECT COUNT(*) FROM target_ports").fetchone()[0]

    print("PurrSh3ll terminal history DB stats")
    print(f"  Commands : {n_cmd}")
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

    exit_ok  = conn.execute("SELECT COUNT(*) FROM commands WHERE exit_code = 0").fetchone()[0]
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
    # elapsed_ms is the sub-second-accurate duration; fall back to the coarse
    # generated duration_ms, and to "n/a" for old schemas that have neither.
    _keys = row.keys()
    if "elapsed_ms" in _keys and row["elapsed_ms"] is not None:
        _dur = f"{row['elapsed_ms']} ms"
    elif "duration_ms" in _keys and row["duration_ms"] is not None:
        _dur = f"{row['duration_ms']} ms"
    else:
        _dur = "n/a"
    print(f"ID        : {row['id']}")
    print(f"Terminal  : {row['terminal']}")
    print(f"Time      : {_ts(row['ts'])} → {_ts(row['ts_end'])}  ({_dur})")
    print(f"Exit code : {row['exit_code']}")
    print(f"CWD       : {row['cwd'] or '-'}")
    print(f"Tags      : {', '.join(tags) or '-'}")
    print(f"Command   :\n  {row['cmd']}")
    if row['output']:
        # output_size is a generated column; older schemas lack it — fall back to len().
        _osz = row["output_size"] if ("output_size" in _keys and row["output_size"] is not None) else len(row["output"])
        print(f"Output ({_osz} bytes):\n{row['output']}")


def cmd_clear(conn, yes):
    count = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    if not yes:
        print(f"This will permanently delete ALL history ({count} commands, findings, targets).")
        answer = input("Type 'yes' to confirm: ").strip().lower()
        if answer != "yes":
            print("Aborted.")
            return
    conn.executescript("""
        PRAGMA foreign_keys = ON;
        DELETE FROM command_tags;
        DELETE FROM findings;
        DELETE FROM target_ports;
        DELETE FROM targets;
        DELETE FROM commands;
        DELETE FROM sqlite_sequence;
    """)
    conn.commit()
    print(f"History cleared ({count} commands deleted). ID counter reset to 1.")


def main():
    ap = argparse.ArgumentParser(description="Query PurrSh3ll terminal history DB")
    ap.add_argument("-n", type=int, default=20, help="Number of results (default 20)")
    ap.add_argument("-q", "--search", metavar="PATTERN", help="Search commands and output")
    ap.add_argument("--all", dest="show_all", action="store_true", help="Show full history")
    ap.add_argument("-t", "--tag", metavar="TAG", help="Show commands tagged with category (e.g. recon, web, exploit)")
    ap.add_argument("--categories", action="store_true", help="List all available categories from tool_categories.json")
    ap.add_argument("--targets", action="store_true", help="Show all discovered targets")
    ap.add_argument("--ports", nargs="?", const="", metavar="IP",
                    help="Show open ports (all targets, or specific IP)")
    ap.add_argument("--findings", action="store_true", help="Show findings")
    ap.add_argument("--stats", action="store_true", help="Show DB statistics")
    ap.add_argument("--show", type=int, metavar="ID", help="Show full details of command by ID")
    ap.add_argument("--clear", action="store_true", help="Delete entire history")
    ap.add_argument("-y", "--yes", action="store_true", help="Skip confirmation for --clear")
    args = ap.parse_args()

    conn = _connect(DEFAULT_DB)

    if args.clear:
        cmd_clear(conn, args.yes)
    elif args.categories:
        conn.close()
        cmd_categories(DEFAULT_DB)
        return
    elif args.tag:
        cmd_category(conn, args.tag, args.n, args.show_all)
    elif args.show_all:
        cmd_all(conn)
    elif args.search:
        cmd_search(conn, args.search, args.n)
    elif args.targets:
        cmd_targets(conn)
    elif args.ports is not None:
        cmd_ports(conn, args.ports or None)
    elif args.findings:
        cmd_findings(conn)
    elif args.stats:
        cmd_stats(conn)
    elif args.show is not None:
        cmd_show(conn, args.show)
    else:
        cmd_list(conn, args.n)

    conn.close()


if __name__ == "__main__":
    main()
