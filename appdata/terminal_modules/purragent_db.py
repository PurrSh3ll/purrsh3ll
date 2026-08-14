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
    mac           TEXT,                    -- not collected yet (pshunter-parity column)
    vendor        TEXT,                    -- not collected yet (pshunter-parity column)
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
    cpe        TEXT,                        -- nmap -sV CPE, drives phase-4 CVE lookup
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
CREATE TABLE IF NOT EXISTS scripts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER,
    port       INTEGER,
    proto      TEXT,
    script     TEXT,                       -- NSE script id (phase 2, -sC)
    output     TEXT,
    UNIQUE (target_id, port, proto, script),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS vulns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER,
    port       INTEGER,                    -- 0 = host-level (hostscript) finding
    proto      TEXT,
    script     TEXT,                       -- NSE script id that produced it (phase 3)
    state      TEXT,                       -- VULNERABLE / LIKELY / EXPOSED
    risk       TEXT,                       -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    cve        TEXT,                       -- comma-joined CVE ids, or NULL
    summary    TEXT,
    UNIQUE (target_id, port, proto, script),
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


def _as_int(v):
    """Coerce to int (models sometimes send '80' or 80.0), or None if not a port."""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def save_engagement(base_dir: str, objective, data: dict, raw_text: str) -> dict:
    """Persist one engagement from the intake extraction.

    `objective` is the shortcode picked from the menu (flag/privesc/vuln/access).
    `data` is the model's structured extraction (target/ports/credentials/
    endpoints/notes); anything missing is simply skipped. `raw_text` is always
    kept verbatim as a 'raw-intake' note, so nothing the user typed is lost even
    if the model under-extracted. Returns a summary dict of what was stored.
    """
    data = data or {}

    conn = _connect(base_dir)
    try:
        cur = conn.cursor()
        ip = _clean(data.get("ip"))
        hostname = _clean(data.get("hostname"))
        url = _clean(data.get("url"))
        label = ip or hostname or url
        cur.execute(
            "INSERT INTO engagements (created, objective, label) VALUES (?, ?, ?)",
            (_now(), _clean(objective), label))
        eng_id = cur.lastrowid

        cur.execute(
            "INSERT INTO targets (engagement_id, ip, hostname, domain, url, os, "
            "platform) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (eng_id, ip, hostname, None, url,
             _clean(data.get("os")), _clean(data.get("platform"))))
        target_id = cur.lastrowid

        # Ports come as a plain number list; services map a name onto a port. Merge
        # them so a service-only port is still recorded.
        svc_by_port = {}
        for s in (data.get("services") or []):
            if isinstance(s, dict):
                pi = _as_int(s.get("port"))
                if pi is not None and _clean(s.get("name")):
                    svc_by_port[pi] = _clean(s.get("name"))
        port_nums = set(svc_by_port)
        for p in (data.get("ports") or []):
            pi = _as_int(p)
            if pi is not None:
                port_nums.add(pi)
        for pnum in sorted(port_nums):
            cur.execute(
                "INSERT INTO ports (target_id, port, proto, service) "
                "VALUES (?, ?, 'tcp', ?)",
                (target_id, pnum, svc_by_port.get(pnum)))
        n_ports = len(port_nums)

        n_creds = 0
        for c in (data.get("credentials") or []):
            if not isinstance(c, dict):
                continue
            user, secret = _clean(c.get("username")), _clean(c.get("secret"))
            if not user and not secret:
                continue
            cur.execute(
                "INSERT INTO credentials (target_id, scope, username, secret, "
                "secret_type, source) VALUES (?, ?, ?, ?, ?, 'user')",
                (target_id, _clean(c.get("scope")), user, secret,
                 _clean(c.get("type") or c.get("secret_type"))))
            n_creds += 1

        n_eps = 0
        for p in (data.get("paths") or []):
            u = _clean(p)
            if not u:
                continue
            cur.execute("INSERT INTO endpoints (target_id, url) VALUES (?, ?)",
                        (target_id, u))
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


def fetch_hosts(base_dir: str) -> list:
    """One row per target (the 'hosts' table), newest first, with its engagement
    objective and open-port count — for the top level of the /target browser."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    try:
        rows = []
        for t in conn.execute(
                "SELECT t.*, e.objective AS objective FROM targets t "
                "LEFT JOIN engagements e ON e.id = t.engagement_id "
                "ORDER BY t.id DESC"):
            d = dict(t)
            d["n_ports"] = conn.execute(
                "SELECT count(*) FROM ports WHERE target_id = ?", (t["id"],)
            ).fetchone()[0]
            rows.append(d)
        return rows
    finally:
        conn.close()


def fetch_ports(base_dir: str, target_id: int) -> list:
    """Ports/services for one host, ordered by port."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ports WHERE target_id = ? ORDER BY port", (target_id,))]
    finally:
        conn.close()


def fetch_findings(base_dir: str, target_id: int, engagement_id: int) -> dict:
    """Credentials, endpoints and notes attached to a target/engagement — shown as
    'findings' in the port detail view."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    try:
        return {
            "credentials": [dict(r) for r in conn.execute(
                "SELECT * FROM credentials WHERE target_id = ?", (target_id,))],
            "endpoints": [dict(r) for r in conn.execute(
                "SELECT * FROM endpoints WHERE target_id = ?", (target_id,))],
            "vulns": [dict(r) for r in conn.execute(
                "SELECT * FROM vulns WHERE target_id = ? ORDER BY port", (target_id,))],
            "notes": [dict(r) for r in conn.execute(
                "SELECT * FROM notes WHERE engagement_id = ? ORDER BY id",
                (engagement_id,))],
        }
    finally:
        conn.close()


def set_service(base_dir: str, target_id: int, port: int, proto: str = "tcp",
                service=None, product=None, version=None, cpe=None) -> None:
    """Enrich an existing port row with detected service/product/version/cpe (phase 2,
    -sV). COALESCE keeps prior values when the scan returns nothing; inserts the row
    if the port isn't present yet."""
    conn = _connect(base_dir)
    try:
        cur = conn.execute(
            "UPDATE ports SET service = COALESCE(?, service), "
            "product = COALESCE(?, product), version = COALESCE(?, version), "
            "cpe = COALESCE(?, cpe) "
            "WHERE target_id = ? AND port = ? AND proto = ?",
            (_clean(service), _clean(product), _clean(version), _clean(cpe),
             target_id, int(port), _clean(proto) or "tcp"))
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO ports (target_id, port, proto, service, product, "
                "version, cpe) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target_id, int(port), _clean(proto) or "tcp", _clean(service),
                 _clean(product), _clean(version), _clean(cpe)))
        conn.commit()
    finally:
        conn.close()


def set_os(base_dir: str, target_id: int, os_name) -> None:
    """Record the detected OS on the target (phase 2, -O)."""
    os_name = _clean(os_name)
    if not os_name:
        return
    conn = _connect(base_dir)
    try:
        conn.execute("UPDATE targets SET os = ? WHERE id = ?", (os_name, target_id))
        conn.commit()
    finally:
        conn.close()


def add_script(base_dir: str, target_id: int, port: int, proto: str,
               script, output) -> None:
    """Store one NSE script's output for a port (phase 2, -sC). Upsert on re-scan."""
    script, output = _clean(script), _clean(output)
    if not script or not output:
        return
    conn = _connect(base_dir)
    try:
        conn.execute(
            "INSERT INTO scripts (target_id, port, proto, script, output) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(target_id, port, proto, script) "
            "DO UPDATE SET output = excluded.output",
            (target_id, int(port), _clean(proto) or "tcp", script, output))
        conn.commit()
    finally:
        conn.close()


def fetch_scripts(base_dir: str, target_id: int, port: int = None) -> list:
    """NSE script output for a target (optionally one port), for the /target detail."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    try:
        if port is None:
            rows = conn.execute("SELECT * FROM scripts WHERE target_id = ? "
                                "ORDER BY port, script", (target_id,))
        else:
            rows = conn.execute("SELECT * FROM scripts WHERE target_id = ? AND "
                                "port = ? ORDER BY script", (target_id, int(port)))
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_vuln(base_dir: str, target_id: int, port: int, proto: str, script,
             state, risk, cve, summary) -> None:
    """Store one phase-3 vuln/auth finding for a port (0 = host-level). Upsert on the
    (target, port, proto, script) key so re-running the scan refreshes it."""
    script, summary = _clean(script), _clean(summary)
    if not script or not summary:
        return
    conn = _connect(base_dir)
    try:
        conn.execute(
            "INSERT INTO vulns (target_id, port, proto, script, state, risk, cve, "
            "summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(target_id, port, proto, script) DO UPDATE SET "
            "state = excluded.state, risk = excluded.risk, cve = excluded.cve, "
            "summary = excluded.summary",
            (target_id, int(port), _clean(proto) or "tcp", script, _clean(state),
             _clean(risk), _clean(cve), summary))
        conn.commit()
    finally:
        conn.close()


def fetch_vulns(base_dir: str, target_id: int) -> list:
    """Phase-3 findings for a target, worst risk first then by port."""
    conn = _connect(base_dir)
    conn.row_factory = sqlite3.Row
    order = ("CASE risk WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
             "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END")
    try:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM vulns WHERE target_id = ? ORDER BY {order}, port",
            (target_id,))]
    finally:
        conn.close()


def add_service(base_dir: str, target_id: int, port: int, proto: str = "tcp",
                service=None, product=None, version=None) -> None:
    """Manually add a port/service to a host (user-supplied, like pshunter's [a])."""
    conn = _connect(base_dir)
    try:
        conn.execute(
            "INSERT INTO ports (target_id, port, proto, service, product, version) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, int(port), _clean(proto) or "tcp", _clean(service),
             _clean(product), _clean(version)))
        conn.commit()
    finally:
        conn.close()


def remove_port(base_dir: str, port_id: int) -> None:
    """Delete one port/service row by id."""
    conn = _connect(base_dir)
    try:
        conn.execute("DELETE FROM ports WHERE id = ?", (port_id,))
        conn.commit()
    finally:
        conn.close()


def remove_engagement(base_dir: str, engagement_id: int) -> None:
    """Delete a target (engagement) and everything tied to it — its target row(s),
    ports, credentials, endpoints and notes."""
    conn = _connect(base_dir)
    try:
        tids = [r[0] for r in conn.execute(
            "SELECT id FROM targets WHERE engagement_id = ?", (engagement_id,))]
        for tid in tids:
            conn.execute("DELETE FROM ports WHERE target_id = ?", (tid,))
            conn.execute("DELETE FROM credentials WHERE target_id = ?", (tid,))
            conn.execute("DELETE FROM endpoints WHERE target_id = ?", (tid,))
            conn.execute("DELETE FROM scripts WHERE target_id = ?", (tid,))
            conn.execute("DELETE FROM vulns WHERE target_id = ?", (tid,))
        conn.execute("DELETE FROM targets WHERE engagement_id = ?", (engagement_id,))
        conn.execute("DELETE FROM notes WHERE engagement_id = ?", (engagement_id,))
        conn.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        conn.commit()
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
            eng["vulns"] = [dict(r) for r in conn.execute(
                "SELECT * FROM vulns WHERE target_id = ? ORDER BY port", (tid,))]
            eng["notes"] = [dict(r) for r in conn.execute(
                "SELECT * FROM notes WHERE engagement_id = ? ORDER BY id", (e["id"],))]
            out.append(eng)
        return out
    finally:
        conn.close()
