"""
terminal_history_db.py — SQLite backend for PurrSh3ll terminal history.

Schema:
  commands      — every command with full output
  command_tags  — many-to-many tags per command (recon, exploit, found_flag, …)
  findings      — extracted discoveries: ports, creds, hashes, CVEs, flags
  targets       — known hosts / IPs
  target_ports  — open ports per target

Usage:
    from core.db.terminal_history_db import TerminalHistoryDB
    db = TerminalHistoryDB("/path/to/terminal_history.db")
    db.init()
    cid = db.insert_command(ts=1700000000, ts_end=1700000005,
                            terminal="terminal_1", cmd="nmap -sV 10.10.10.161",
                            exit_code=0, output="...", cwd="/root/htb/forest")
    db.add_tags(cid, ["recon", "scan"])
    db.add_finding(command_id=cid, finding_type="port", value="445",
                   target="10.10.10.161", confidence=1.0,
                   raw_line="445/tcp open  microsoft-ds")
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous  = NORMAL;

-- ── commands ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,          -- unix epoch, command start
    ts_end       INTEGER,                   -- unix epoch, command end
    duration_ms  INTEGER GENERATED ALWAYS AS (
                     CASE WHEN ts_end IS NOT NULL THEN (ts_end - ts) * 1000 END
                 ) STORED,
    terminal     TEXT    NOT NULL DEFAULT 'terminal_1',
    cmd          TEXT    NOT NULL,
    exit_code    INTEGER,
    output       TEXT,                      -- full stdout+stderr
    output_size  INTEGER GENERATED ALWAYS AS (
                     CASE WHEN output IS NOT NULL THEN length(output) ELSE 0 END
                 ) STORED,
    cwd          TEXT,                      -- working directory at execution time
    entry_type   TEXT    NOT NULL DEFAULT 'command'
                         CHECK(entry_type IN ('command','note','bookmark','error'))
);

CREATE INDEX IF NOT EXISTS idx_commands_ts  ON commands(ts);
CREATE INDEX IF NOT EXISTS idx_commands_cmd ON commands(cmd);

-- ── command_tags ──────────────────────────────────────────────────────────
--
-- Tag vocabulary (enforced by application, not DB):
--   Phase tags : recon | scan | web | smb | ftp | ssh | ldap | snmp | sql
--                exploit | reverse_shell | privesc | lateral | persistence | cleanup
--   Finding tags: found_port | found_cred | found_hash | found_flag | found_cve
--                 found_user | found_host | found_path | found_service
--   State tags : success | failed | partial | manual
--
CREATE TABLE IF NOT EXISTS command_tags (
    command_id  INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    tag         TEXT    NOT NULL,
    PRIMARY KEY (command_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_tags_tag ON command_tags(tag);

-- ── findings ──────────────────────────────────────────────────────────────
--
-- finding_type values:
--   port | credential | hash | flag | cve | user | host | path | service | note
--
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id   INTEGER REFERENCES commands(id) ON DELETE SET NULL,
    ts           INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    finding_type TEXT    NOT NULL,
    value        TEXT    NOT NULL,          -- the finding itself
    target       TEXT,                      -- host/IP this finding relates to
    port         INTEGER,                   -- port number if relevant
    protocol     TEXT,                      -- tcp | udp
    service      TEXT,                      -- http | smb | ssh …
    confidence   REAL    NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    raw_line     TEXT,                      -- exact output line it was extracted from
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_type   ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);

-- ── targets ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL UNIQUE,
    hostname  TEXT,
    os_guess  TEXT,
    notes     TEXT
);

-- ── target_ports ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS target_ports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    protocol   TEXT    NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp')),
    state      TEXT    NOT NULL DEFAULT 'open' CHECK(state IN ('open','filtered','closed')),
    service    TEXT,
    version    TEXT,
    notes      TEXT,
    UNIQUE(target_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_target ON target_ports(target_id);
"""

# ---------------------------------------------------------------------------
# DB class
# ---------------------------------------------------------------------------

class TerminalHistoryDB:
    """Thin wrapper around the terminal history SQLite database."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    # ── connection management ───────────────────────────────────────────────

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30,
            )
            conn.row_factory = sqlite3.Row
            self._conn = conn
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        conn = self.connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    # ── schema ─────────────────────────────────────────────────────────────

    def init(self) -> None:
        """Create all tables and indexes (idempotent)."""
        conn = self.connect()
        conn.executescript(_DDL)
        conn.commit()

    # ── commands ───────────────────────────────────────────────────────────

    def insert_command(
        self,
        ts: int,
        cmd: str,
        terminal: str = "terminal_1",
        ts_end: Optional[int] = None,
        exit_code: Optional[int] = None,
        output: Optional[str] = None,
        cwd: Optional[str] = None,
        entry_type: str = "command",
    ) -> int:
        """Insert a command record and return its id."""
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO commands (ts, ts_end, terminal, cmd, exit_code, output, cwd, entry_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ts, ts_end, terminal, cmd, exit_code, output, cwd, entry_type),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_recent_commands(
        self,
        limit: int = 50,
        tag: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        """Return recent commands, optionally filtered by tag."""
        with self._cursor() as cur:
            if tag:
                cur.execute(
                    """
                    SELECT c.* FROM commands c
                    JOIN command_tags t ON t.command_id = c.id
                    WHERE t.tag = ?
                    ORDER BY c.ts DESC LIMIT ?
                    """,
                    (tag, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM commands ORDER BY ts DESC LIMIT ?", (limit,)
                )
            return cur.fetchall()

    def search_commands(self, pattern: str, limit: int = 100) -> List[sqlite3.Row]:
        """Full-text search over cmd and output (LIKE)."""
        like = f"%{pattern}%"
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM commands WHERE cmd LIKE ? OR output LIKE ? ORDER BY ts DESC LIMIT ?",
                (like, like, limit),
            )
            return cur.fetchall()

    # ── tags ───────────────────────────────────────────────────────────────

    def add_tags(self, command_id: int, tags: List[str]) -> None:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT OR IGNORE INTO command_tags (command_id, tag) VALUES (?, ?)",
                [(command_id, t.strip().lower()) for t in tags if t.strip()],
            )

    def get_tags(self, command_id: int) -> List[str]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT tag FROM command_tags WHERE command_id = ? ORDER BY tag",
                (command_id,),
            )
            return [row["tag"] for row in cur.fetchall()]

    def commands_by_tag(self, tag: str, limit: int = 200) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT c.* FROM commands c
                JOIN command_tags t ON t.command_id = c.id
                WHERE t.tag = ?
                ORDER BY c.ts DESC LIMIT ?
                """,
                (tag, limit),
            )
            return cur.fetchall()

    # ── findings ───────────────────────────────────────────────────────────

    def add_finding(
        self,
        finding_type: str,
        value: str,
        command_id: Optional[int] = None,
        target: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        service: Optional[str] = None,
        confidence: float = 1.0,
        raw_line: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings
                    (command_id, ts, finding_type, value, target,
                     port, protocol, service, confidence, raw_line, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (command_id, int(time.time()), finding_type, value,
                 target, port, protocol, service, confidence, raw_line, notes),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_findings(
        self,
        finding_type: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        clauses: List[str] = []
        params: List = []
        if finding_type:
            clauses.append("finding_type = ?")
            params.append(finding_type)
        if target:
            clauses.append("target = ?")
            params.append(target)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._cursor() as cur:
            cur.execute(f"SELECT * FROM findings {where} ORDER BY ts DESC", params)
            return cur.fetchall()

    # ── targets ────────────────────────────────────────────────────────────

    def upsert_target(
        self,
        ip: str,
        hostname: Optional[str] = None,
        os_guess: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT id FROM targets WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row:
                tid = row["id"]
                cur.execute(
                    """
                    UPDATE targets SET
                        hostname = COALESCE(?, hostname),
                        os_guess = COALESCE(?, os_guess),
                        notes    = COALESCE(?, notes)
                    WHERE id = ?
                    """,
                    (hostname, os_guess, notes, tid),
                )
                return tid
            else:
                cur.execute(
                    "INSERT INTO targets (ip, hostname, os_guess, notes) VALUES (?, ?, ?, ?)",
                    (ip, hostname, os_guess, notes),
                )
                return cur.lastrowid  # type: ignore[return-value]

    def upsert_port(
        self,
        target_id: int,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: Optional[str] = None,
        version: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                "SELECT id FROM target_ports WHERE target_id = ? AND port = ? AND protocol = ?",
                (target_id, port, protocol),
            )
            row = cur.fetchone()
            if row:
                pid = row["id"]
                cur.execute(
                    """
                    UPDATE target_ports SET
                        state   = ?,
                        service = COALESCE(?, service),
                        version = COALESCE(?, version),
                        notes   = COALESCE(?, notes)
                    WHERE id = ?
                    """,
                    (state, service, version, notes, pid),
                )
                return pid
            else:
                cur.execute(
                    """
                    INSERT INTO target_ports
                        (target_id, port, protocol, state, service, version, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, port, protocol, state, service, version, notes),
                )
                return cur.lastrowid  # type: ignore[return-value]

    def get_targets(self) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM targets ORDER BY ip")
            return cur.fetchall()

    def get_ports(self, target_id: int) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM target_ports WHERE target_id = ? ORDER BY port",
                (target_id,),
            )
            return cur.fetchall()

    def trim_to_limit(self, max_entries: int) -> int:
        """Delete oldest commands so at most max_entries remain. Returns number deleted."""
        with self._cursor() as cur:
            total = cur.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
            to_delete = total - max_entries
            if to_delete <= 0:
                return 0
            cur.execute(
                """
                DELETE FROM commands WHERE id IN (
                    SELECT id FROM commands ORDER BY ts ASC LIMIT ?
                )
                """,
                (to_delete,),
            )
            cur.execute("DELETE FROM command_tags WHERE command_id NOT IN (SELECT id FROM commands)")
            self._conn.commit()
            return to_delete

    def clear(self) -> None:
        """Delete all history data (commands, tags, findings, targets, ports)."""
        with self._cursor() as cur:
            cur.executescript("""
                PRAGMA foreign_keys = ON;
                DELETE FROM command_tags;
                DELETE FROM findings;
                DELETE FROM target_ports;
                DELETE FROM targets;
                DELETE FROM commands;
            """)
        self._conn.commit()

    # ── convenience ────────────────────────────────────────────────────────

    def export_jsonl(self, limit: int = 0) -> List[dict]:
        """
        Export commands as list of dicts in the original JSONL format.
        Compatible with existing psfix / psnext / psreport readers.
        """
        rows = self.get_recent_commands(limit=limit or 100_000)
        result = [
            {
                "ts":        r["ts"],
                "ts_end":    r["ts_end"],
                "terminal":  r["terminal"],
                "cmd":       r["cmd"],
                "exit_code": r["exit_code"],
                "output":    r["output"] or "",
            }
            for r in rows
        ]
        result.reverse()  # chronological order
        return result


# ---------------------------------------------------------------------------
# CLI — quick sanity check
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys

    db_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test_terminal_history.db"
    db = TerminalHistoryDB(db_path)
    db.init()
    print(f"[OK] Schema created at {db_path}")

    cid = db.insert_command(
        ts=int(time.time()),
        ts_end=int(time.time()) + 3,
        terminal="terminal_1",
        cmd="nmap -sV -p 445 10.10.10.161",
        exit_code=0,
        output="445/tcp open  microsoft-ds\nService Info: OS: Windows",
        cwd="/root/htb/forest",
    )
    print(f"[OK] Inserted command id={cid}")

    db.add_tags(cid, ["recon", "scan", "smb", "found_port"])
    print(f"[OK] Tags: {db.get_tags(cid)}")

    fid = db.add_finding(
        command_id=cid,
        finding_type="port", value="445",
        target="10.10.10.161", port=445, protocol="tcp",
        service="microsoft-ds", confidence=1.0,
        raw_line="445/tcp open  microsoft-ds",
    )
    print(f"[OK] Finding id={fid}")

    tid = db.upsert_target(ip="10.10.10.161", hostname="FOREST", os_guess="Windows Server 2019")
    db.upsert_port(tid, 445, service="microsoft-ds")
    print(f"[OK] Target id={tid}")

    db.close()
    print("[OK] Done.")
