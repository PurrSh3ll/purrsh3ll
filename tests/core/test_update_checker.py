"""Tests for the update checker (core/update_checker.py).

Covers the pure version helpers and the check_for_updates decision logic. All
network/git access is stubbed via monkeypatch, so these tests are fully offline
and deterministic.
"""

from core import update_checker as uc


# --------------------------------------------------------------------------- #
# _normalize
# --------------------------------------------------------------------------- #
def test_normalize_strips_v_prefix_and_whitespace():
    assert uc._normalize("  v1.2.3 ") == "1.2.3"
    assert uc._normalize("V2.0") == "2.0"
    assert uc._normalize("1.4.0") == "1.4.0"


# --------------------------------------------------------------------------- #
# _parse
# --------------------------------------------------------------------------- #
def test_parse_orders_versions_numerically_not_lexically():
    # The whole point of using packaging.version: 1.10.0 > 1.9.0.
    assert uc._parse("1.10.0") > uc._parse("1.9.0")
    assert uc._parse("v2.0.0") > uc._parse("1.99.99")


def test_parse_returns_none_for_garbage():
    assert uc._parse("not-a-version") is None
    assert uc._parse("") is None


# --------------------------------------------------------------------------- #
# _highest_tag
# --------------------------------------------------------------------------- #
def test_highest_tag_picks_max_and_keeps_raw_form():
    tags = ["v1.2.0", "v1.10.0", "v1.9.0"]
    assert uc._highest_tag(tags) == "v1.10.0"


def test_highest_tag_skips_unparseable_entries():
    tags = ["garbage", "v1.0.0", "", "also-bad", "v1.5.0"]
    assert uc._highest_tag(tags) == "v1.5.0"


def test_highest_tag_all_invalid_returns_none():
    assert uc._highest_tag(["nope", "", "bad"]) is None
    assert uc._highest_tag([]) is None


# --------------------------------------------------------------------------- #
# get_local_version — fallback path (no .git present)
# --------------------------------------------------------------------------- #
def test_get_local_version_falls_back_to_bundled_version(tmp_path):
    # tmp_path has no .git, so the function must return __version__ (normalized).
    assert uc.get_local_version(str(tmp_path)) == uc._normalize(uc.__version__)


# --------------------------------------------------------------------------- #
# check_for_updates — decision logic (remote/local stubbed)
# --------------------------------------------------------------------------- #
def _stub(monkeypatch, local, latest):
    monkeypatch.setattr(uc, "get_local_version", lambda _p: local)
    monkeypatch.setattr(uc, "get_remote_version", lambda _p: latest)


def test_check_reports_update_available(monkeypatch):
    _stub(monkeypatch, local="1.3.0", latest="1.4.0")
    res = uc.check_for_updates("/whatever")
    assert res["status"] == "update_available"
    assert res["local"] == "1.3.0"
    assert res["latest"] == "1.4.0"


def test_check_reports_up_to_date_when_equal(monkeypatch):
    _stub(monkeypatch, local="1.3.0", latest="1.3.0")
    assert uc.check_for_updates("/whatever")["status"] == "up_to_date"


def test_check_reports_up_to_date_when_local_is_newer(monkeypatch):
    _stub(monkeypatch, local="1.5.0", latest="1.4.0")
    assert uc.check_for_updates("/whatever")["status"] == "up_to_date"


def test_check_numeric_ordering_not_lexical(monkeypatch):
    # 1.10.0 must be seen as newer than 1.9.0 (string compare would fail).
    _stub(monkeypatch, local="1.9.0", latest="1.10.0")
    assert uc.check_for_updates("/whatever")["status"] == "update_available"


def test_check_error_when_remote_unavailable(monkeypatch):
    _stub(monkeypatch, local="1.3.0", latest=None)
    res = uc.check_for_updates("/whatever")
    assert res["status"] == "error"
    assert res["latest"] is None
