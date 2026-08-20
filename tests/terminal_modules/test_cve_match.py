"""Tests for pshunter's version/CPE/CVE matching primitives (cve_match).

These implement the deliberately strict "fewer but better-verified CVEs" gate:
numeric version comparison, CPE URI parsing, and cpeMatch-row matching that
refuses coarse fingerprints and open-ended ranges (the big false-positive
sources). Pure functions — no DB.
"""

from cve_match import _ver_key, _ver_cmp, _cve_sort_key, _cpe_parts, _ver_in_match


# --------------------------------------------------------------------------- #
# _ver_key / _ver_cmp
# --------------------------------------------------------------------------- #
def test_ver_key_extracts_numeric_components():
    assert _ver_key("8.2p1") == (8, 2, 1)
    assert _ver_key("1.2.3") == (1, 2, 3)
    assert _ver_key("v4") == (4,)


def test_ver_key_empty_for_none_or_blank():
    assert _ver_key(None) == ()
    assert _ver_key("") == ()


def test_ver_cmp_orders_numerically():
    assert _ver_cmp("1.2", "1.10") == -1        # 2 < 10, not lexical
    assert _ver_cmp("2.0", "1.9") == 1
    assert _ver_cmp("1.2.3", "1.2.3") == 0


def test_ver_cmp_pads_shorter_version():
    assert _ver_cmp("1.0", "1.0.0") == 0


# --------------------------------------------------------------------------- #
# _cve_sort_key
# --------------------------------------------------------------------------- #
def test_cve_sort_newest_first():
    ids = ["CVE-2019-1", "CVE-2021-5", "CVE-2020-9"]
    assert sorted(ids, key=_cve_sort_key) == ["CVE-2021-5", "CVE-2020-9", "CVE-2019-1"]


def test_cve_sort_key_same_year_by_sequence():
    assert _cve_sort_key("CVE-2021-9999") < _cve_sort_key("CVE-2021-1000")


def test_cve_sort_key_non_matching():
    assert _cve_sort_key("not-a-cve") == (0, 0)


# --------------------------------------------------------------------------- #
# _cpe_parts
# --------------------------------------------------------------------------- #
def test_cpe_22_parsed():
    assert _cpe_parts("cpe:/a:openbsd:openssh:8.2") == ("openbsd", "openssh", "8.2")


def test_cpe_23_parsed():
    assert _cpe_parts("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*") == \
        ("openbsd", "openssh", "8.2")


def test_cpe_version_any_becomes_none():
    assert _cpe_parts("cpe:/a:v:p:*")[2] is None
    assert _cpe_parts("cpe:/a:v:p:-")[2] is None
    assert _cpe_parts("cpe:/a:v:p")[2] is None


def test_cpe_invalid_returns_none():
    assert _cpe_parts("http://not-a-cpe") is None
    assert _cpe_parts("") is None
    assert _cpe_parts("cpe:weirdformat") is None


def test_cpe_missing_vendor_or_product_rejected():
    assert _cpe_parts("cpe:/a::openssh:8.2") is None      # empty vendor


# --------------------------------------------------------------------------- #
# _ver_in_match — exact
# --------------------------------------------------------------------------- #
def _range(v, exact=None, vsi=None, vse=None, vei=None, vee=None):
    return _ver_in_match(v, exact, vsi, vse, vei, vee)


def test_exact_match():
    assert _range("8.2", exact="8.2") is True
    assert _range("8.2.0", exact="8.2") is True    # coarser-equal after padding


def test_exact_rejects_coarser_fingerprint():
    # A bare "8" must NOT be taken as "8.2" (the biggest false-positive source).
    assert _range("8", exact="8.2") is False


def test_exact_rejects_more_specific_mismatch():
    assert _range("8.2.1", exact="8.2") is False


# --------------------------------------------------------------------------- #
# _ver_in_match — ranges (strict)
# --------------------------------------------------------------------------- #
def test_bare_major_never_in_range():
    assert _range("4", vsi="1.0", vei="9.0") is False


def test_open_ended_range_dropped():
    assert _range("1.5", vsi="1.0") is False        # start only
    assert _range("1.5", vei="2.0") is False        # end only


def test_closed_inclusive_range_matches_inside_and_bounds():
    assert _range("1.5", vsi="1.0", vei="2.0") is True
    assert _range("1.0", vsi="1.0", vei="2.0") is True     # start inclusive
    assert _range("2.0", vsi="1.0", vei="2.0") is True     # end inclusive


def test_closed_range_excludes_outside():
    assert _range("0.9", vsi="1.0", vei="2.0") is False
    assert _range("2.5", vsi="1.0", vei="2.0") is False


def test_exclusive_bounds():
    # start-excluding: version == start is out; end-excluding: version == end is out.
    assert _range("1.0", vse="1.0", vei="2.0") is False
    assert _range("2.0", vsi="1.0", vee="2.0") is False
    assert _range("1.9", vsi="1.0", vee="2.0") is True
