"""Tests for purragent's engagement store (purragent_db).

A self-contained SQLite store; every function opens/closes its own connection
against base_dir/appdata/purragent.db. We point base_dir at a throwaway tmp tree,
so these run against a real (tiny) SQLite DB with no mocking — exercising the
intake save, CRUD helpers, upsert/dedup semantics, risk ordering, the
session-ephemeral reset(), and cascade delete.
"""

import json

import pytest

import purragent_db as db


@pytest.fixture
def base(tmp_path):
    (tmp_path / "appdata").mkdir()
    return str(tmp_path)


def _engagement(base, **overrides):
    """Create one engagement, return (engagement_id, target_id)."""
    data = {"ip": "10.10.10.5", "hostname": "target.htb"}
    data.update(overrides)
    res = db.save_engagement(base, "flag", data, raw_text="raw intake text")
    tid = db.fetch_hosts(base)[0]["id"]
    return res["engagement_id"], tid


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #
def test_clean_trims_and_nulls_blanks():
    assert db._clean("  hello ") == "hello"
    assert db._clean("") is None
    assert db._clean("   ") is None
    assert db._clean(None) is None


def test_as_int_coerces_or_none():
    assert db._as_int("80") == 80
    assert db._as_int("  443 ") == 443
    assert db._as_int(22) == 22
    assert db._as_int("abc") is None
    assert db._as_int(None) is None


# --------------------------------------------------------------------------- #
# save_engagement
# --------------------------------------------------------------------------- #
def test_save_engagement_returns_summary_and_persists(base):
    data = {
        "ip": "10.10.10.5",
        "ports": [80, 443, 80],                       # duplicate 80
        "services": [{"port": 22, "name": "ssh"}],    # service-only port
        "credentials": [
            {"username": "admin", "secret": "pass", "type": "password"},
            {"username": "", "secret": ""},           # empty → skipped
        ],
        "paths": ["/admin", "/login", ""],            # blank dropped
        "notes": "interesting box",
    }
    res = db.save_engagement(base, "flag", data, raw_text="the raw text")
    assert res["objective"] == "flag"
    assert res["label"] == "10.10.10.5"
    assert res["ports"] == 3          # {22, 80, 443} deduped
    assert res["credentials"] == 1    # empty pair skipped
    assert res["endpoints"] == 2      # blank path dropped


def test_save_engagement_merges_and_sorts_ports(base):
    eng_id, tid = _engagement(
        base, ports=[443, 80], services=[{"port": 22, "name": "ssh"}])
    ports = db.fetch_ports(base, tid)
    assert [p["port"] for p in ports] == [22, 80, 443]
    ssh = [p for p in ports if p["port"] == 22][0]
    assert ssh["service"] == "ssh"


def test_save_engagement_keeps_raw_intake_note(base):
    eng_id, tid = _engagement(base)
    findings = db.fetch_findings(base, tid, eng_id)
    kinds = {n["kind"] for n in findings["notes"]}
    assert "raw-intake" in kinds


def test_fetch_hosts_reports_port_count(base):
    _engagement(base, ports=[22, 80])
    host = db.fetch_hosts(base)[0]
    assert host["ip"] == "10.10.10.5"
    assert host["n_ports"] == 2
    assert host["objective"] == "flag"


# --------------------------------------------------------------------------- #
# credentials — upsert / empty preservation / validation
# --------------------------------------------------------------------------- #
def test_add_credential_upserts_on_same_key(base):
    _eng, tid = _engagement(base)
    cid1 = db.add_credential(base, tid, "root", "toor", "password")
    cid2 = db.add_credential(base, tid, "root", "toor", "password")
    assert cid1 == cid2
    assert len(db.fetch_credentials(base, tid)) == 1


def test_add_credential_distinct_secret_is_new_row(base):
    _eng, tid = _engagement(base)
    db.add_credential(base, tid, "root", "toor", "password")
    db.add_credential(base, tid, "root", "hunter2", "password")
    assert len(db.fetch_credentials(base, tid)) == 2


def test_add_credential_preserves_empty_login(base):
    _eng, tid = _engagement(base)
    db.add_credential(base, tid, None, None, "none")   # anonymous / null login
    creds = db.fetch_credentials(base, tid)
    assert len(creds) == 1
    assert creds[0]["username"] == "" and creds[0]["secret"] == ""


def test_set_cred_validated_records_port_and_tool(base):
    _eng, tid = _engagement(base)
    cid = db.add_credential(base, tid, "root", "toor", "password")
    db.set_cred_validated(base, cid, True, port=22, tool="nxc")
    db.set_cred_validated(base, cid, True, port=22, tool="nxc")   # dedup port
    db.set_cred_validated(base, cid, True, port=445)

    cred = db.fetch_credentials(base, tid)[0]
    assert cred["validated"] == 1
    assert json.loads(cred["valid_on"]) == [22, 445]
    assert cred["valid_tool"] == "nxc"


def test_set_cred_validated_marks_invalid(base):
    _eng, tid = _engagement(base)
    cid = db.add_credential(base, tid, "root", "wrong", "password")
    db.set_cred_validated(base, cid, False)
    assert db.fetch_credentials(base, tid)[0]["validated"] == -1


# --------------------------------------------------------------------------- #
# usernames — dedup / empty drop
# --------------------------------------------------------------------------- #
def test_add_username_dedups_and_drops_empty(base):
    _eng, tid = _engagement(base)
    db.add_username(base, tid, "admin")
    db.add_username(base, tid, "admin")     # dup ignored
    db.add_username(base, tid, "   ")       # blank dropped
    names = [u["username"] for u in db.fetch_usernames(base, tid)]
    assert names == ["admin"]


# --------------------------------------------------------------------------- #
# vulns — risk ordering
# --------------------------------------------------------------------------- #
def test_fetch_vulns_orders_worst_risk_first(base):
    _eng, tid = _engagement(base)
    db.add_vuln(base, tid, 80, "tcp", "s-low", "LIKELY", "LOW", None, "low one")
    db.add_vuln(base, tid, 445, "tcp", "s-crit", "VULNERABLE", "CRITICAL",
                "CVE-2017-0144", "eternalblue")
    db.add_vuln(base, tid, 22, "tcp", "s-med", "EXPOSED", "MEDIUM", None, "medium one")

    risks = [v["risk"] for v in db.fetch_vulns(base, tid)]
    assert risks == ["CRITICAL", "MEDIUM", "LOW"]


def test_add_vuln_upserts_on_conflict(base):
    _eng, tid = _engagement(base)
    db.add_vuln(base, tid, 80, "tcp", "s1", "LIKELY", "LOW", None, "first")
    db.add_vuln(base, tid, 80, "tcp", "s1", "VULNERABLE", "HIGH", None, "updated")
    vulns = db.fetch_vulns(base, tid)
    assert len(vulns) == 1
    assert vulns[0]["risk"] == "HIGH" and vulns[0]["summary"] == "updated"


# --------------------------------------------------------------------------- #
# ports enrichment — set_service COALESCE, add_script upsert
# --------------------------------------------------------------------------- #
def test_set_service_inserts_then_coalesces(base):
    _eng, tid = _engagement(base)
    db.set_service(base, tid, 8080, service="http")          # inserts new port
    db.set_service(base, tid, 8080, version="1.0")           # keeps service, adds version
    port = [p for p in db.fetch_ports(base, tid) if p["port"] == 8080][0]
    assert port["service"] == "http"
    assert port["version"] == "1.0"


def test_add_script_upserts_output(base):
    _eng, tid = _engagement(base)
    db.add_script(base, tid, 80, "tcp", "http-title", "Old title")
    db.add_script(base, tid, 80, "tcp", "http-title", "New title")
    scripts = db.fetch_scripts(base, tid, 80)
    assert len(scripts) == 1
    assert scripts[0]["output"] == "New title"


# --------------------------------------------------------------------------- #
# reset / cascade delete
# --------------------------------------------------------------------------- #
def test_reset_wipes_store(base):
    _engagement(base)
    assert db.fetch_hosts(base)          # non-empty
    db.reset(base)
    assert db.fetch_hosts(base) == []    # fresh empty DB re-created


def test_reset_on_missing_db_is_safe(base):
    db.reset(base)   # never created — must not raise
    assert db.fetch_hosts(base) == []


def test_remove_engagement_cascades(base):
    eng_id, tid = _engagement(base, ports=[22])
    db.add_credential(base, tid, "root", "toor", "password")
    db.remove_engagement(base, eng_id)

    assert db.fetch_hosts(base) == []
    assert db.fetch_ports(base, tid) == []
    assert db.fetch_credentials(base, tid) == []
    assert db.fetch_all(base) == []
