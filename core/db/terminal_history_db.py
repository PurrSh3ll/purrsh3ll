"""
terminal_history_db.py — SQLite backend for PurrSh3ll terminal history.

Schema overview:
  sessions      — logical engagement sessions (one per Claude Code run / user session)
  commands      — every command with full output, linked to a session
  command_tags  — many-to-many tags per command (recon, exploit, found_flag, …)
  findings      — extracted discoveries: ports, creds, hashes, CVEs, flags
  targets       — known hosts / IPs seen during a session
  target_ports  — open ports per target

Usage:
    from core.db.terminal_history_db import TerminalHistoryDB
    db = TerminalHistoryDB("/path/to/terminal_history.db")
    db.init()
    sid = db.new_session(label="HTB — Forest", mode="ctf")
    cid = db.insert_command(session_id=sid, ts=1700000000, ts_end=1700000005,
                            terminal="terminal_1", cmd="nmap -sV 10.10.10.161",
                            exit_code=0, output="...", cwd="/root/htb/forest")
    db.add_tags(cid, ["recon", "scan"])
    db.add_finding(session_id=sid, command_id=cid, finding_type="port",
                   value="445", target="10.10.10.161", confidence=1.0,
                   raw_line="445/tcp open  microsoft-ds")
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous  = NORMAL;

-- ── sessions ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    ended_at    INTEGER,
    label       TEXT,                       -- e.g. "HTB — Forest" or "pentest acme"
    mode        TEXT,                       -- "ctf" | "pentest" | "general"
    target_ip   TEXT,                       -- primary target for this session
    notes       TEXT
);

-- ── commands ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
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

CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_ts      ON commands(ts);
CREATE INDEX IF NOT EXISTS idx_commands_cmd     ON commands(cmd);

-- ── command_tags ──────────────────────────────────────────────────────────
--
-- Predefined tag vocabulary (not enforced by DB — enforced by application):
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
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    command_id  INTEGER REFERENCES commands(id) ON DELETE SET NULL,
    ts          INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    finding_type TEXT NOT NULL,
    value       TEXT NOT NULL,             -- the finding itself
    target      TEXT,                      -- host/IP this finding relates to
    port        INTEGER,                   -- port number if relevant
    protocol    TEXT,                      -- tcp | udp
    service     TEXT,                      -- http | smb | ssh …
    confidence  REAL    NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    raw_line    TEXT,                      -- the exact output line it was extracted from
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_type    ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_target  ON findings(target);

-- ── targets ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    ip          TEXT    NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,                      -- e.g. "Linux 4.x" | "Windows Server 2019"
    notes       TEXT,
    UNIQUE(session_id, ip)
);

-- ── target_ports ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS target_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp')),
    state       TEXT    NOT NULL DEFAULT 'open' CHECK(state IN ('open','filtered','closed')),
    service     TEXT,                      -- e.g. "http", "microsoft-ds"
    version     TEXT,                      -- banner / version string
    notes       TEXT,
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

    # ── sessions ───────────────────────────────────────────────────────────

    def new_session(
        self,
        label: str = "",
        mode: str = "general",
        target_ip: str = "",
        notes: str = "",
    ) -> int:
        """Open a new session and return its id."""
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (started_at, label, mode, target_ip, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(time.time()), label or None, mode or None,
                 target_ip or None, notes or None),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def close_session(self, session_id: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (int(time.time()), session_id),
            )

    def get_session(self, session_id: int) -> Optional[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            return cur.fetchone()

    def list_sessions(self, limit: int = 50) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            )
            return cur.fetchall()

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
        session_id: Optional[int] = None,
    ) -> int:
        """Insert a command record and return its id."""
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO commands
                    (session_id, ts, ts_end, terminal, cmd, exit_code, output, cwd, entry_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, ts, ts_end, terminal, cmd,
                 exit_code, output, cwd, entry_type),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_recent_commands(
        self,
        limit: int = 50,
        session_id: Optional[int] = None,
        tag: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        """Return recent commands, optionally filtered by session or tag."""
        with self._cursor() as cur:
            if tag:
                cur.execute(
                    """
                    SELECT c.* FROM commands c
                    JOIN command_tags t ON t.command_id = c.id
                    WHERE t.tag = ?
                      AND (? IS NULL OR c.session_id = ?)
                    ORDER BY c.ts DESC LIMIT ?
                    """,
                    (tag, session_id, session_id, limit),
                )
            elif session_id is not None:
                cur.execute(
                    "SELECT * FROM commands WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
                    (session_id, limit),
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

    def commands_by_tag(
        self, tag: str, session_id: Optional[int] = None, limit: int = 200
    ) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            if session_id is not None:
                cur.execute(
                    """
                    SELECT c.* FROM commands c
                    JOIN command_tags t ON t.command_id = c.id
                    WHERE t.tag = ? AND c.session_id = ?
                    ORDER BY c.ts DESC LIMIT ?
                    """,
                    (tag, session_id, limit),
                )
            else:
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
        session_id: Optional[int] = None,
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
                    (session_id, command_id, ts, finding_type, value, target,
                     port, protocol, service, confidence, raw_line, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, command_id, int(time.time()), finding_type, value,
                 target, port, protocol, service, confidence, raw_line, notes),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_findings(
        self,
        session_id: Optional[int] = None,
        finding_type: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        clauses: List[str] = []
        params: List = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
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
        session_id: Optional[int] = None,
        hostname: Optional[str] = None,
        os_guess: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO targets (session_id, ip, hostname, os_guess, notes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id, ip) DO UPDATE SET
                    hostname = COALESCE(excluded.hostname, hostname),
                    os_guess = COALESCE(excluded.os_guess, os_guess),
                    notes    = COALESCE(excluded.notes, notes)
                """,
                (session_id, ip, hostname, os_guess, notes),
            )
            cur.execute(
                "SELECT id FROM targets WHERE session_id IS ? AND ip = ?",
                (session_id, ip),
            )
            row = cur.fetchone()
            return row["id"] if row else cur.lastrowid  # type: ignore[return-value]

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
                """
                INSERT INTO target_ports (target_id, port, protocol, state, service, version, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, port, protocol) DO UPDATE SET
                    state   = excluded.state,
                    service = COALESCE(excluded.service, service),
                    version = COALESCE(excluded.version, version),
                    notes   = COALESCE(excluded.notes, notes)
                """,
                (target_id, port, protocol, state, service, version, notes),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_targets(self, session_id: Optional[int] = None) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            if session_id is not None:
                cur.execute(
                    "SELECT * FROM targets WHERE session_id = ? ORDER BY ip", (session_id,)
                )
            else:
                cur.execute("SELECT * FROM targets ORDER BY ip")
            return cur.fetchall()

    def get_ports(self, target_id: int) -> List[sqlite3.Row]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM target_ports WHERE target_id = ? ORDER BY port",
                (target_id,),
            )
            return cur.fetchall()

    # ── convenience queries ────────────────────────────────────────────────

    def session_summary(self, session_id: int) -> dict:
        """Return a summary dict useful for psreport / psnext."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS cnt, MIN(ts) AS first, MAX(ts) AS last "
                "FROM commands WHERE session_id = ?",
                (session_id,),
            )
            cmd_row = cur.fetchone()

            cur.execute(
                "SELECT finding_type, COUNT(*) AS cnt "
                "FROM findings WHERE session_id = ? GROUP BY finding_type",
                (session_id,),
            )
            findings_by_type = {row["finding_type"]: row["cnt"] for row in cur.fetchall()}

            cur.execute(
                "SELECT tag, COUNT(*) AS cnt FROM command_tags ct "
                "JOIN commands c ON c.id = ct.command_id "
                "WHERE c.session_id = ? GROUP BY tag ORDER BY cnt DESC",
                (session_id,),
            )
            tags = {row["tag"]: row["cnt"] for row in cur.fetchall()}

            cur.execute(
                "SELECT COUNT(*) AS cnt FROM targets WHERE session_id = ?",
                (session_id,),
            )
            target_count = cur.fetchone()["cnt"]

        return {
            "session_id": session_id,
            "command_count": cmd_row["cnt"] if cmd_row else 0,
            "first_ts": cmd_row["first"] if cmd_row else None,
            "last_ts": cmd_row["last"] if cmd_row else None,
            "findings": findings_by_type,
            "tags": tags,
            "target_count": target_count,
        }

    def export_jsonl(self, session_id: Optional[int] = None, limit: int = 0) -> List[dict]:
        """
        Export commands as list of dicts in the original JSONL format.
        Compatible with existing psfix / psnext / psreport readers.
        """
        rows = self.get_recent_commands(
            limit=limit or 100_000, session_id=session_id
        )
        result = []
        for r in rows:
            result.append({
                "ts":        r["ts"],
                "ts_end":    r["ts_end"],
                "terminal":  r["terminal"],
                "cmd":       r["cmd"],
                "exit_code": r["exit_code"],
                "output":    r["output"] or "",
            })
        # export_jsonl returns newest-first; reverse for chronological order
        result.reverse()
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

    sid = db.new_session(label="Demo session", mode="ctf", target_ip="10.10.10.161")
    print(f"[OK] New session id={sid}")

    cid = db.insert_command(
        session_id=sid,
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
        session_id=sid, command_id=cid,
        finding_type="port", value="445",
        target="10.10.10.161", port=445, protocol="tcp",
        service="microsoft-ds", confidence=1.0,
        raw_line="445/tcp open  microsoft-ds",
    )
    print(f"[OK] Finding id={fid}")

    tid = db.upsert_target(ip="10.10.10.161", session_id=sid,
                           hostname="FOREST", os_guess="Windows Server 2019")
    db.upsert_port(tid, 445, service="microsoft-ds")
    print(f"[OK] Target id={tid}")

    summary = db.session_summary(sid)
    print(f"[OK] Summary:\n{json.dumps(summary, indent=2)}")

    db.close_session(sid)
    db.close()
    print("[OK] Done.")
