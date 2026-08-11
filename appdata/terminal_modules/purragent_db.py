"""purragent hacking-mode engagement store.

A small, self-contained SQLite database for the target intake collected when
hacking mode is enabled. Deliberately separate from pshunter.db: purragent owns
the *engagement* meta (objective, one target at a time) that pshunter's
host-centric schema doesn't model. Holds credentials, so the file is gitignored.

Schema is relational (lightweight, agent-friendly SELECTs) with a generic `edges`
table left as a hedge for later attack-path / graph analysis — not populated by
the intake yet.
"""

import os
import sqlite3
from datetime import datetime, timezone


def _db_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "purragent.db")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created    TEXT,
    objective  TEXT,                      -- flag / privesc / vuln / access
    label      TEXT,
    status     TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    ip            TEXT,
    hostname      TEXT,
    domain        TEXT,
    url           TEXT,
    os            TEXT,
    platform      TEXT,                    -- linux / windows / ad / web / other
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE TABLE IF NOT EXISTS ports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER,
    port       INTEGER,
    proto      TEXT,
    service    TEXT,
    product    TEXT,
    version    TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,
    scope       TEXT,                      -- service/url/host it applies to
    username    TEXT,
    secret      TEXT,
    secret_type TEXT,                      -- password/hash/ssh_key/token/api_key
    source      TEXT DEFAULT 'user',       -- user / discovered
    validated   INTEGER DEFAULT 0,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER,
    url        TEXT,
    method     TEXT,
    params     TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS notes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER,
    kind          TEXT,                    -- 'raw-intake' / 'note'
    text          TEXT,
    created       TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
-- Future-proofing for graph / attack-path analysis (cred->service works_on,
-- host->host pivots_to/trusts). Not populated by the intake yet.
CREATE TABLE IF NOT EXISTS edges (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    src_type TEXT, src_id INTEGER,
    relation TEXT,
    dst_type TEXT, dst_id INTEGER
);
"""


def _connect(base_dir: str) -> sqlite3.Connection:
    """Open the DB (creating it + schema on first use) with FKs on."""
    conn = sqlite3.connect(_db_path(base_dir))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def reset(base_dir: str) -> None:
    """Delete the DB and its WAL/SHM sidecars. The engagement store is session-
    ephemeral (it holds credentials), so it is wiped on purragent start AND exit —
    clearing on start too means a crash never leaks a previous session's data.
    Safe to call when the file doesn't exist. No long-lived connection exists (each
    op opens/closes its own), so removing the file between ops is safe."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(_db_path(base_dir) + suffix)
        except OSError:
            pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(v):
    """Trim strings; treat blanks/None as missing so we don't store empties."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def save_engagement(base_dir: str, objective, data: dict, raw_text: str) -> dict:
    """Persist one engagement from the intake extraction.

    `objective` is the shortcode picked from the menu (flag/privesc/vuln/access).
    `data` is the model's structured extraction (target/ports/credentials/
    endpoints/notes); anything missing is simply skipped. `raw_text` is always
    kept verbatim as a 'raw-intake' note, so nothing the user typed is lost even
    if the model under-extracted. Returns a summary dict of what was stored.
    """
    data = data or {}
    tgt = data.get("target") or {}
    ports = data.get("ports") or []
    creds = data.get("credentials") or []
    eps = data.get("endpoints") or []

    conn = _connect(base_dir)
    try:
        cur = conn.cursor()
        label = (_clean(tgt.get("ip")) or _clean(tgt.get("hostname"))
                 or _clean(tgt.get("url")) or _clean(tgt.get("domain")))
        cur.execute(
            "INSERT INTO engagements (created, objective, label) VALUES (?, ?, ?)",
            (_now(), _clean(objective), label))
        eng_id = cur.lastrowid

        cur.execute(
            "INSERT INTO targets (engagement_id, ip, hostname, domain, url, os, "
            "platform) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (eng_id, _clean(tgt.get("ip")), _clean(tgt.get("hostname")),
             _clean(tgt.get("domain")), _clean(tgt.get("url")),
             _clean(tgt.get("os")), _clean(tgt.get("platform"))))
        target_id = cur.lastrowid

        n_ports = 0
        for p in ports:
            if not isinstance(p, dict):
                continue
            port = p.get("port")
            try:
                port = int(port) if port is not None else None
            except (TypeError, ValueError):
                port = None
            if port is None:
                continue
            cur.execute(
                "INSERT INTO ports (target_id, port, proto, service, product, "
                "version) VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, port, _clean(p.get("proto")), _clean(p.get("service")),
                 _clean(p.get("product")), _clean(p.get("version"))))
            n_ports += 1

        n_creds = 0
        for c in creds:
            if not isinstance(c, dict):
                continue
            user, secret = _clean(c.get("username")), _clean(c.get("secret"))
            if not user and not secret:
                continue
            cur.execute(
                "INSERT INTO credentials (target_id, scope, username, secret, "
                "secret_type, source) VALUES (?, ?, ?, ?, ?, 'user')",
                (target_id, _clean(c.get("scope")), user, secret,
                 _clean(c.get("secret_type"))))
            n_creds += 1

        n_eps = 0
        for e in eps:
            if not isinstance(e, dict):
                continue
            url = _clean(e.get("url"))
            if not url:
                continue
            cur.execute(
                "INSERT INTO endpoints (target_id, url, method, params) "
                "VALUES (?, ?, ?, ?)",
                (target_id, url, _clean(e.get("method")), _clean(e.get("params"))))
            n_eps += 1

        note = _clean(data.get("notes"))
        if note:
            cur.execute("INSERT INTO notes (engagement_id, kind, text, created) "
                        "VALUES (?, 'note', ?, ?)", (eng_id, note, _now()))
        raw = _clean(raw_text)
        if raw:
            cur.execute("INSERT INTO notes (engagement_id, kind, text, created) "
                        "VALUES (?, 'raw-intake', ?, ?)", (eng_id, raw, _now()))

        conn.commit()
        return {"engagement_id": eng_id, "objective": _clean(objective),
                "label": label, "ports": n_ports, "credentials": n_creds,
                "endpoints": n_eps}
    finally:
        conn.close()


def fetch_all(base_dir: str) -> list:
    """Every engagement (newest first) with its target, ports, credentials,
    endpoints and notes nested in — for the /target view. Returns [] if empty."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    try:
        out = []
        for e in conn.execute("SELECT * FROM engagements ORDER BY id DESC"):
            eng = dict(e)
            t = conn.execute("SELECT * FROM targets WHERE engagement_id = ? "
                             "LIMIT 1", (e["id"],)).fetchone()
            eng["target"] = dict(t) if t else None
            tid = t["id"] if t else -1
            eng["ports"] = [dict(r) for r in conn.execute(
                "SELECT * FROM ports WHERE target_id = ? ORDER BY port", (tid,))]
            eng["credentials"] = [dict(r) for r in conn.execute(
                "SELECT * FROM credentials WHERE target_id = ?", (tid,))]
            eng["endpoints"] = [dict(r) for r in conn.execute(
                "SELECT * FROM endpoints WHERE target_id = ?", (tid,))]
            eng["notes"] = [dict(r) for r in conn.execute(
                "SELECT * FROM notes WHERE engagement_id = ? ORDER BY id", (e["id"],))]
            out.append(eng)
        return out
    finally:
        conn.close()
