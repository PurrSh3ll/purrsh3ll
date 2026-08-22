"""Regression tests for hacktools port_discovery argument handling.

Covers two small-model robustness fixes:

  1. `timing` sent as a number (3) instead of "T3" must NOT crash with
     'int' object has no attribute 'upper' — it is coerced to a T0-T5 string.
  2. an explicit port list like "1-1024" put in `range` (an enum field) is
     routed to `ports` instead of failing, so the scan runs on the first try.

The builder only constructs the nmap argv (it does not run nmap), so these are
pure and offline. _is_root is forced False for a deterministic scan flag.
"""

import re

import pytest

import hacktools_tools as h


@pytest.fixture(autouse=True)
def _non_root(monkeypatch):
    # Deterministic scan type regardless of who runs the suite (root → -sS).
    monkeypatch.setattr(h, "_is_root", lambda: False)


# --------------------------------------------------------------------------- #
# _norm_timing — the actual bug
# --------------------------------------------------------------------------- #
def test_timing_int_is_coerced_not_crashing():
    # The original bug: `3 .upper()` raised AttributeError.
    assert h._norm_timing({"timing": 3}) == "T3"


def test_timing_accepts_various_forms():
    assert h._norm_timing({"timing": "T3"}) == "T3"
    assert h._norm_timing({"timing": "t3"}) == "T3"
    assert h._norm_timing({"timing": "3"}) == "T3"
    assert h._norm_timing({"timing": 0}) == "T0"


def test_timing_defaults_to_t4():
    assert h._norm_timing({}) == "T4"
    assert h._norm_timing({"timing": None}) == "T4"
    assert h._norm_timing({"timing": ""}) == "T4"


def test_timing_invalid_raises():
    for bad in ("T9", "9", "fast", "TT3"):
        with pytest.raises(ValueError):
            h._norm_timing({"timing": bad})


def test_nmap_tuning_also_coerces_int_timing():
    # The shared helper used by every scan tool must not crash on int timing.
    flags = h._nmap_tuning({"timing": 2})
    assert "-T2" in flags
    assert "-Pn" in flags               # host_discovery defaults false


# --------------------------------------------------------------------------- #
# _b_port_discovery — argv building + range→ports routing
# --------------------------------------------------------------------------- #
def _argv(args):
    argv, binary = h._b_port_discovery(args)
    assert binary == "nmap"
    return argv


def test_default_scan_is_fast_top1000_pn():
    argv = _argv({"host": "10.0.0.1"})
    assert argv[0] == "nmap"
    assert "-sT" in argv                # non-root connect scan
    assert "-Pn" in argv                # host_discovery false → assume up
    assert "-T4" in argv                # default timing
    assert "--top-ports" in argv and "1000" in argv
    assert argv[-1] == "10.0.0.1"


def test_range_keyword_low_expands_ports():
    argv = _argv({"host": "10.0.0.1", "range": "low"})
    assert "-p" in argv and "1-32767" in argv


def test_numeric_range_is_routed_to_ports():
    # The second failure in the report: "1-1024" in `range`.
    argv = _argv({"host": "10.0.0.1", "range": "1-1024"})
    assert "-p" in argv
    assert "1-1024" in argv
    assert "--top-ports" not in argv    # not treated as the fast keyword


def test_explicit_ports_arg_wins():
    argv = _argv({"host": "10.0.0.1", "range": "full", "ports": "22,80,443"})
    assert "22,80,443" in argv
    assert "-p-" not in argv            # explicit ports override the range keyword


def test_int_timing_in_full_call_builds_valid_flag():
    # End-to-end regression: the exact shape from the debug log (timing as int).
    argv = _argv({"host": "192.168.0.38", "range": "low", "timing": 3,
                  "host_discovery": True})
    assert "-T3" in argv
    assert "-Pn" not in argv            # host_discovery true → nmap pings first
    assert "1-32767" in argv


def test_host_discovery_true_drops_pn():
    argv = _argv({"host": "10.0.0.1", "host_discovery": True})
    assert "-Pn" not in argv


# --------------------------------------------------------------------------- #
# validation errors
# --------------------------------------------------------------------------- #
def test_non_numeric_bad_range_raises_with_hint():
    with pytest.raises(ValueError) as e:
        h._b_port_discovery({"host": "10.0.0.1", "range": "medium"})
    assert "ports" in str(e.value)      # error now points at the `ports` field


def test_bad_protocol_raises():
    with pytest.raises(ValueError):
        h._b_port_discovery({"host": "10.0.0.1", "protocol": "icmp"})


def test_missing_host_raises():
    with pytest.raises(ValueError):
        h._b_port_discovery({"range": "fast"})
