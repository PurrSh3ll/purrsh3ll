"""Tests for the data-wipe registry and executor (core/data_wipe.py).

These exercise the destructive path logic against a throwaway base_path built
under tmp_path — never the real appdata tree. Focus: the registry's ids/defaults
(so the "erase" dialog can't silently pre-check something dangerous), path
resolution, and that wipe() removes exactly the selected categories, keeps
directories in place (empty), skips unknown ids, and isolates failures.
"""

import os

from core import data_wipe


# --------------------------------------------------------------------------- #
# build_wipe_items — registry contract
# --------------------------------------------------------------------------- #
def test_registry_has_stable_ids():
    items = data_wipe.build_wipe_items("/base")
    ids = {it.id for it in items}
    # A representative, load-bearing subset (not the full set, to allow growth).
    assert {"history_db", "pshunter_db", "credentials", "docker"} <= ids


def test_dangerous_categories_default_off():
    defaults = {it.id: it.default for it in data_wipe.build_wipe_items("/base")}
    # Things the user authored or must re-enter are never pre-checked.
    assert defaults["credentials"] is False
    assert defaults["docker"] is False
    assert defaults["system_variables"] is False
    assert defaults["snippets"] is False


def test_accumulating_engagement_data_defaults_on():
    defaults = {it.id: it.default for it in data_wipe.build_wipe_items("/base")}
    assert defaults["history_db"] is True
    assert defaults["pshunter_db"] is True


def test_paths_resolved_against_base_path():
    items = {it.id: it for it in data_wipe.build_wipe_items("/base")}
    pshunter = items["pshunter_db"]
    assert os.path.join("/base", "appdata", "pshunter.db") in pshunter.paths
    assert os.path.join("/base", "appdata", "hosts_ledger.json") in pshunter.paths


# --------------------------------------------------------------------------- #
# _remove_path
# --------------------------------------------------------------------------- #
def test_remove_path_deletes_file(tmp_path):
    f = tmp_path / "gone.txt"
    f.write_text("x")
    assert data_wipe._remove_path(str(f)) == 1
    assert not f.exists()


def test_remove_path_empties_but_keeps_directory(tmp_path):
    d = tmp_path / "cache"
    d.mkdir()
    (d / "a.txt").write_text("x")
    (d / "b.txt").write_text("y")
    data_wipe._remove_path(str(d))
    # Directory itself stays (app still finds it) but is now empty.
    assert d.is_dir()
    assert list(d.iterdir()) == []


def test_remove_path_handles_glob(tmp_path):
    (tmp_path / "app.log").write_text("1")
    (tmp_path / "app.log.1").write_text("2")
    (tmp_path / "keep.txt").write_text("3")
    removed = data_wipe._remove_path(str(tmp_path / "app.log*"))
    assert removed == 2
    assert (tmp_path / "keep.txt").exists()


def test_remove_path_missing_is_noop(tmp_path):
    assert data_wipe._remove_path(str(tmp_path / "nope.txt")) == 0


# --------------------------------------------------------------------------- #
# wipe — end to end on a fake appdata tree
# --------------------------------------------------------------------------- #
def _make_appdata(base):
    ad = base / "appdata"
    ad.mkdir(parents=True, exist_ok=True)
    (ad / "pshunter.db").write_text("engagement")
    (ad / "hosts_ledger.json").write_text("[]")
    (ad / "kev.txt").write_text("reference-data")   # NOT in any wipe list
    return ad


def test_wipe_removes_selected_category(tmp_path):
    ad = _make_appdata(tmp_path)
    report = data_wipe.wipe(str(tmp_path), ["pshunter_db"])

    ok, _detail = report["pshunter_db"]
    assert ok is True
    assert not (ad / "pshunter.db").exists()
    assert not (ad / "hosts_ledger.json").exists()


def test_wipe_keeps_reference_and_unselected_data(tmp_path):
    ad = _make_appdata(tmp_path)
    (ad / "snippets.json").write_text("mine")

    data_wipe.wipe(str(tmp_path), ["pshunter_db"])

    # Reference data and unselected categories are untouched.
    assert (ad / "kev.txt").read_text() == "reference-data"
    assert (ad / "snippets.json").read_text() == "mine"


def test_wipe_skips_unknown_ids(tmp_path):
    _make_appdata(tmp_path)
    report = data_wipe.wipe(str(tmp_path), ["not_a_real_category"])
    assert "not_a_real_category" not in report


def test_wipe_reports_per_category(tmp_path):
    _make_appdata(tmp_path)
    report = data_wipe.wipe(str(tmp_path), ["pshunter_db"])
    assert set(report.keys()) == {"pshunter_db"}
    ok, detail = report["pshunter_db"]
    assert ok is True and isinstance(detail, str)
