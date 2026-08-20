"""Tests for the terminal history store (core/db/terminal_history_db).

The app's main command/finding/target history. Runs against a real SQLite DB in
tmp_path (no mocking): the two-phase insert/update logger, recent/search
queries, tags, findings, target upsert (COALESCE), and the separate
pstool_commands table that must stay out of normal history.
"""

import pytest

from core.db.terminal_history_db import TerminalHistoryDB


@pytest.fixture
def db(tmp_path):
    d = TerminalHistoryDB(tmp_path / "history.db")
    d.init()
    yield d
    d.close()


# --------------------------------------------------------------------------- #
# insert / recent / two-phase update
# --------------------------------------------------------------------------- #
def test_insert_and_get_recent(db):
    cid = db.insert_command(ts=100, cmd="ls -la")
    rows = db.get_recent_commands()
    assert len(rows) == 1
    assert rows[0]["id"] == cid
    assert rows[0]["cmd"] == "ls -la"


def test_recent_orders_newest_first(db):
    db.insert_command(ts=100, cmd="old")
    db.insert_command(ts=200, cmd="new")
    assert db.get_recent_commands()[0]["cmd"] == "new"


def test_recent_respects_limit(db):
    for i in range(3):
        db.insert_command(ts=100 + i, cmd=f"c{i}")
    assert len(db.get_recent_commands(limit=2)) == 2


def test_two_phase_update_finalizes_row(db):
    cid = db.insert_command(ts=100, cmd="scan", exit_code=None, output=None)
    db.update_command(cid, ts_end=150, exit_code=0, output="done", elapsed_ms=50_000)
    row = db.get_recent_commands()[0]
    assert row["exit_code"] == 0
    assert row["output"] == "done"
    assert row["elapsed_ms"] == 50_000


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #
def test_search_matches_cmd_and_output(db):
    db.insert_command(ts=100, cmd="nmap 10.0.0.1", output="22/tcp open ssh")
    assert db.search_commands("nmap")
    assert db.search_commands("22/tcp")        # matches on output
    assert db.search_commands("nonexistent") == []


# --------------------------------------------------------------------------- #
# tags
# --------------------------------------------------------------------------- #
def test_tags_are_lowercased_stripped_and_deduped(db):
    cid = db.insert_command(ts=100, cmd="gobuster")
    db.add_tags(cid, ["Recon", " recon ", "web", ""])
    assert db.get_tags(cid) == ["recon", "web"]


def test_recent_filtered_by_tag(db):
    a = db.insert_command(ts=100, cmd="tagged")
    db.insert_command(ts=200, cmd="untagged")
    db.add_tags(a, ["recon"])
    rows = db.get_recent_commands(tag="recon")
    assert [r["cmd"] for r in rows] == ["tagged"]


def test_commands_by_tag(db):
    a = db.insert_command(ts=100, cmd="web-thing")
    db.add_tags(a, ["web"])
    assert [r["id"] for r in db.commands_by_tag("web")] == [a]


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
def test_add_and_filter_findings(db):
    db.add_finding("cve", "CVE-2021-4034", target="10.0.0.1")
    db.add_finding("hash", "aaa:bbb", target="10.0.0.2")
    assert len(db.get_findings(finding_type="cve")) == 1
    assert len(db.get_findings(target="10.0.0.1")) == 1
    assert db.get_findings(finding_type="credential") == []


# --------------------------------------------------------------------------- #
# targets — upsert COALESCE
# --------------------------------------------------------------------------- #
def test_upsert_target_keeps_prior_values(db):
    tid = db.upsert_target("10.0.0.1", hostname="host.htb")
    tid2 = db.upsert_target("10.0.0.1", os_guess="linux")   # hostname omitted
    assert tid == tid2
    row = db.connect().execute(
        "SELECT hostname, os_guess FROM targets WHERE id = ?", (tid,)).fetchone()
    assert row["hostname"] == "host.htb"     # preserved via COALESCE
    assert row["os_guess"] == "linux"        # newly set


# --------------------------------------------------------------------------- #
# pstool_commands — separate table, invisible to normal history
# --------------------------------------------------------------------------- #
def test_pstool_commands_stay_out_of_normal_history(db):
    db.insert_command(ts=100, cmd="real command")
    db.insert_pstool_command(ts=101, cmd="psfix internal")
    cmds = [r["cmd"] for r in db.get_recent_commands()]
    assert "real command" in cmds
    assert "psfix internal" not in cmds


def test_pstool_two_phase_update(db):
    pid = db.insert_pstool_command(ts=100, cmd="psnext")
    db.update_pstool_command(pid, ts_end=110, exit_code=1, output="err")
    row = db.connect().execute(
        "SELECT exit_code, output FROM pstool_commands WHERE id = ?", (pid,)).fetchone()
    assert row["exit_code"] == 1
    assert row["output"] == "err"
