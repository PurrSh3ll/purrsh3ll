"""Tests for pshunter's discovery-scope parser (target_parse.parse_discovery_target).

Validates a scan scope (CIDR / bare IP taken as /24 / inclusive range) and turns
it into the nmap target tokens the discovery phase uses. Getting this wrong means
scanning the wrong range, so the edge cases (bad IP, reversed/oversized range,
IPv4-only ranges, /24 compaction vs explicit expansion) matter. Pure function.
"""

from target_parse import parse_discovery_target as parse


# --------------------------------------------------------------------------- #
# empty / invalid
# --------------------------------------------------------------------------- #
def test_empty_is_rejected():
    ok, err, parsed = parse("   ")
    assert ok is False and parsed == {}
    assert "empty" in err


def test_bad_bare_ip_rejected():
    ok, err, _ = parse("999.1.1.1")
    assert ok is False
    assert "valid IP" in err


def test_bad_cidr_rejected():
    ok, err, _ = parse("10.0.0.0/33")
    assert ok is False
    assert "subnet" in err


# --------------------------------------------------------------------------- #
# bare IP -> /24
# --------------------------------------------------------------------------- #
def test_bare_ipv4_becomes_slash24():
    ok, err, p = parse("10.10.10.5")
    assert ok is True and err == ""
    assert p["scope"] == "10.10.10.0/24"
    assert p["hosts"] == 256
    assert p["targets"] == ["10.10.10.0/24"]


# --------------------------------------------------------------------------- #
# CIDR
# --------------------------------------------------------------------------- #
def test_cidr_passthrough():
    ok, _err, p = parse("192.168.1.0/24")
    assert ok is True
    assert p["scope"] == "192.168.1.0/24"
    assert p["hosts"] == 256
    assert p["targets"] == ["192.168.1.0/24"]


def test_small_cidr_host_count():
    ok, _err, p = parse("10.0.0.0/30")
    assert ok is True
    assert p["hosts"] == 4


# --------------------------------------------------------------------------- #
# ranges — same /24 compaction
# --------------------------------------------------------------------------- #
def test_range_octet_end_same_24_is_compacted():
    ok, _err, p = parse("10.10.10.5-10")
    assert ok is True
    assert p["hosts"] == 6
    assert p["targets"] == ["10.10.10.5-10"]
    assert p["scope"] == "10.10.10.5-10.10.10.10"


def test_range_full_end_same_24_is_compacted():
    ok, _err, p = parse("10.10.10.5-10.10.10.20")
    assert ok is True
    assert p["hosts"] == 16
    assert p["targets"] == ["10.10.10.5-20"]


# --------------------------------------------------------------------------- #
# ranges — spanning /24s -> explicit expansion
# --------------------------------------------------------------------------- #
def test_range_across_24_is_expanded_to_list():
    ok, _err, p = parse("10.10.10.250-10.10.11.5")
    assert ok is True
    assert p["hosts"] == 12
    assert len(p["targets"]) == 12
    assert p["targets"][0] == "10.10.10.250"
    assert p["targets"][-1] == "10.10.11.5"


def test_range_too_large_across_24_rejected():
    ok, err, _ = parse("10.10.0.0-10.10.255.255")
    assert ok is False
    assert "too large" in err


# --------------------------------------------------------------------------- #
# ranges — validation errors
# --------------------------------------------------------------------------- #
def test_range_reversed_rejected():
    ok, err, _ = parse("10.10.10.20-10")
    assert ok is False
    assert "before its start" in err


def test_range_bad_start_rejected():
    ok, err, _ = parse("notanip-10")
    assert ok is False
    assert "range start" in err


def test_range_bad_octet_end_rejected():
    ok, err, _ = parse("10.10.10.5-999")
    assert ok is False
    assert "0-255 octet" in err


def test_range_bad_full_end_rejected():
    ok, err, _ = parse("10.10.10.5-1.2.3.999")
    assert ok is False
    assert "range end is not a valid" in err


def test_ipv6_range_rejected():
    ok, err, _ = parse("fe80::1-fe80::5")
    assert ok is False
    assert "IPv4 only" in err


# --------------------------------------------------------------------------- #
# IPv6 bare
# --------------------------------------------------------------------------- #
def test_bare_ipv6_becomes_slash64():
    ok, _err, p = parse("fe80::1")
    assert ok is True
    assert p["scope"].endswith("/64")
