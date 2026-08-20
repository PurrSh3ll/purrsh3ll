"""Tests for psai's provider-profile / API-key resolution helpers (psai).

These decide which provider profile is used, which API key is loaded (OS keyring
first, then the gitignored JSON fallback), and how per-profile params/temperature
are parsed. Bugs here are the classic "wrong key / wrong model / ignored
setting" connection failures. All pure/config-driven — no LLM call is made.
"""

import json
import sys
import types

import pytest

import psai


# --------------------------------------------------------------------------- #
# _active_profile
# --------------------------------------------------------------------------- #
def test_active_profile_returned_by_name():
    config = {"api_providers": {"active": "p1",
                                "profiles": [{"name": "p0"}, {"name": "p1", "model": "x"}]}}
    assert psai._active_profile(config) == {"name": "p1", "model": "x"}


def test_active_profile_empty_when_unset():
    assert psai._active_profile({"api_providers": {"profiles": [{"name": "p0"}]}}) == {}


def test_active_profile_empty_when_name_missing():
    config = {"api_providers": {"active": "ghost", "profiles": [{"name": "p0"}]}}
    assert psai._active_profile(config) == {}


# --------------------------------------------------------------------------- #
# _resolve_profile
# --------------------------------------------------------------------------- #
def test_resolve_defaults_to_active_when_no_arg():
    config = {"api_providers": {"active": "p1", "profiles": [{"name": "p1"}]}}
    assert psai._resolve_profile(config, None) == {"name": "p1"}


def test_resolve_by_explicit_name():
    config = {"api_providers": {"active": "p1",
                                "profiles": [{"name": "p1"}, {"name": "p2", "model": "m"}]}}
    assert psai._resolve_profile(config, "p2") == {"name": "p2", "model": "m"}


def test_resolve_unknown_name_returns_empty(capsys):
    config = {"api_providers": {"active": "p1", "profiles": [{"name": "p1"}]}}
    assert psai._resolve_profile(config, "nope") == {}
    assert "not found" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------- #
# _load_api_key
# --------------------------------------------------------------------------- #
def _fake_keyring(monkeypatch, get):
    fake = types.ModuleType("keyring")
    fake.get_password = get
    monkeypatch.setitem(sys.modules, "keyring", fake)


def test_api_key_from_keyring(monkeypatch, tmp_path):
    _fake_keyring(monkeypatch, lambda service, name: "KEYRING_SECRET")
    assert psai._load_api_key("openai", str(tmp_path)) == "KEYRING_SECRET"


def test_api_key_json_fallback_when_keyring_empty(monkeypatch, tmp_path):
    _fake_keyring(monkeypatch, lambda service, name: "")   # nothing in keyring
    (tmp_path / "appdata").mkdir()
    (tmp_path / "appdata" / "api_keys.json").write_text(json.dumps({"openai": "JSON_KEY"}))
    assert psai._load_api_key("openai", str(tmp_path)) == "JSON_KEY"


def test_api_key_json_fallback_when_keyring_raises(monkeypatch, tmp_path):
    def _boom(service, name):
        raise RuntimeError("no keyring backend")
    _fake_keyring(monkeypatch, _boom)
    (tmp_path / "appdata").mkdir()
    (tmp_path / "appdata" / "api_keys.json").write_text(json.dumps({"claude": "CK"}))
    assert psai._load_api_key("claude", str(tmp_path)) == "CK"


def test_api_key_missing_returns_empty(monkeypatch, tmp_path):
    _fake_keyring(monkeypatch, lambda service, name: "")
    assert psai._load_api_key("openai", str(tmp_path)) == ""


# --------------------------------------------------------------------------- #
# _parse_custom_params
# --------------------------------------------------------------------------- #
def test_custom_params_none_when_absent():
    assert psai._parse_custom_params({}) is None
    assert psai._parse_custom_params({"custom_params": ""}) is None


def test_custom_params_valid_json():
    assert psai._parse_custom_params({"custom_params": '{"top_p": 0.9}'}) == {"top_p": 0.9}


def test_custom_params_invalid_json_returns_none(capsys):
    assert psai._parse_custom_params({"custom_params": "{not json"}) is None
    assert "custom_params" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------- #
# _profile_temperature
# --------------------------------------------------------------------------- #
def test_temperature_parsed_as_float():
    assert psai._profile_temperature({"temperature": "0.7"}) == 0.7
    assert psai._profile_temperature({"temperature": 0.5}) == 0.5
    assert psai._profile_temperature({"temperature": "0"}) == 0.0


def test_temperature_none_when_unset_or_bad():
    assert psai._profile_temperature({}) is None
    assert psai._profile_temperature({"temperature": ""}) is None
    assert psai._profile_temperature({"temperature": None}) is None
    assert psai._profile_temperature({"temperature": "hot"}) is None
