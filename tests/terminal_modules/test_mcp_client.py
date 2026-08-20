"""Tests for the MCP client's pure/file-backed helpers (mcp_client).

We cover the parts that need no network or live server: tool-name namespacing,
external-output capping, built-in detection, JSON-RPC extraction (raw + SSE
framing), catalog short-description derivation, RAG index-text composition, and
the token / tool-cache file stores. Token tests force the keyring path to fail
(injecting a raising fake module) so the gitignored JSON fallback is exercised
deterministically and no real keyring entries are touched.
"""

import json
import os
import sys
import types

import pytest

import mcp_client as mc


# --------------------------------------------------------------------------- #
# namespacing
# --------------------------------------------------------------------------- #
def test_namespaced_roundtrip():
    ns = mc._namespaced("demo", "ping")
    assert ns == "mcp__demo__ping"
    assert mc.split_namespaced(ns) == ("demo", "ping")


def test_split_preserves_tool_name_with_separator():
    ns = mc._namespaced("demo", "do__thing")
    assert mc.split_namespaced(ns) == ("demo", "do__thing")


def test_split_non_namespaced_returns_none():
    assert mc.split_namespaced("plainname") == (None, "plainname")


# --------------------------------------------------------------------------- #
# _cap_external
# --------------------------------------------------------------------------- #
def test_cap_external_leaves_short_text():
    r = mc._cap_external({"text": "short"})
    assert r["text"] == "short"


def test_cap_external_truncates_long_text():
    n = mc.MAX_EXTERNAL_OUTPUT
    r = mc._cap_external({"text": "A" * (n + 50)})
    assert r["text"].startswith("A" * n)
    assert "truncated" in r["text"]
    assert "50 more chars" in r["text"]


def test_cap_external_ignores_non_string():
    r = mc._cap_external({"other": 123})
    assert r == {"other": 123}


# --------------------------------------------------------------------------- #
# is_builtin_server
# --------------------------------------------------------------------------- #
def test_builtin_detected_from_args_path():
    spec = {"args": [os.path.join("appdata", "mcp_servers", "toolkit_server.py")]}
    assert mc.is_builtin_server(spec) is True


def test_external_server_not_builtin():
    assert mc.is_builtin_server({"args": ["/usr/bin/some-server"]}) is False
    assert mc.is_builtin_server({}) is False


# --------------------------------------------------------------------------- #
# _extract_jsonrpc
# --------------------------------------------------------------------------- #
def test_extract_jsonrpc_from_raw_json():
    msg = mc._extract_jsonrpc('{"id": 1, "result": "ok"}', want_id=1)
    assert msg["result"] == "ok"


def test_extract_jsonrpc_id_mismatch_returns_none():
    assert mc._extract_jsonrpc('{"id": 1, "result": "ok"}', want_id=2) is None


def test_extract_jsonrpc_from_sse_frames():
    body = 'event: message\ndata: {"id": 7, "result": "hi"}\n\n'
    msg = mc._extract_jsonrpc(body, want_id=7)
    assert msg["result"] == "hi"


def test_extract_jsonrpc_picks_matching_id_among_many():
    body = 'data: {"id": 1, "result": "a"}\ndata: {"id": 2, "result": "b"}\n'
    assert mc._extract_jsonrpc(body, want_id=2)["result"] == "b"


def test_extract_jsonrpc_any_id_when_none():
    assert mc._extract_jsonrpc('{"id": 9, "result": "z"}', want_id=None)["result"] == "z"


def test_extract_jsonrpc_garbage_returns_none():
    assert mc._extract_jsonrpc("not json at all", want_id=1) is None


# --------------------------------------------------------------------------- #
# _short_from_description
# --------------------------------------------------------------------------- #
def test_short_takes_first_sentence():
    assert mc._short_from_description("Do a thing. Then more.") == "Do a thing"


def test_short_collapses_whitespace():
    assert mc._short_from_description("read   a\n  file") == "read a file"


def test_short_strips_single_trailing_period():
    assert mc._short_from_description("Just this.") == "Just this"


def test_short_falls_back_to_tool_name():
    assert mc._short_from_description("", tool_name="pinger") == "pinger"


def test_short_truncates_to_maxlen():
    out = mc._short_from_description("x" * 200, maxlen=20)
    assert len(out) == 20
    assert out.endswith("…")


# --------------------------------------------------------------------------- #
# _index_text_from_tool
# --------------------------------------------------------------------------- #
def test_index_text_composes_title_desc_params():
    t = {
        "name": "ping",
        "title": "Ping Host",
        "description": "Check if a host is up.",
        "inputSchema": {"properties": {
            "host": {"description": "target host"},
            "count": {},
        }},
    }
    text = mc._index_text_from_tool(t)
    assert "Ping Host" in text
    assert "Check if a host is up." in text
    assert "host: target host" in text
    assert "count" in text


def test_index_text_omits_title_equal_to_name():
    t = {"name": "ping", "title": "ping", "description": "desc"}
    text = mc._index_text_from_tool(t)
    assert text == "desc"


def test_index_text_empty_tool_is_empty():
    assert mc._index_text_from_tool({}) == ""


# --------------------------------------------------------------------------- #
# token store — JSON fallback (keyring forced to fail)
# --------------------------------------------------------------------------- #
@pytest.fixture
def no_keyring(monkeypatch):
    fake = types.ModuleType("keyring")

    def _raise(*a, **k):
        raise RuntimeError("keyring disabled for test")

    fake.get_password = _raise
    fake.set_password = _raise
    fake.delete_password = _raise
    monkeypatch.setitem(sys.modules, "keyring", fake)
    return fake


def test_save_and_load_token_json_fallback(tmp_path, no_keyring):
    (tmp_path / "appdata").mkdir()
    mc.save_token(str(tmp_path), "burp", "secret-token")
    assert mc.load_token(str(tmp_path), "burp") == "secret-token"


def test_saved_token_file_is_private(tmp_path, no_keyring):
    (tmp_path / "appdata").mkdir()
    mc.save_token(str(tmp_path), "burp", "tok")
    path = mc._token_json_path(str(tmp_path))
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600


def test_load_missing_token_returns_empty(tmp_path, no_keyring):
    assert mc.load_token(str(tmp_path), "nope") == ""


def test_empty_token_is_not_saved(tmp_path, no_keyring):
    (tmp_path / "appdata").mkdir()
    mc.save_token(str(tmp_path), "burp", "")
    assert not os.path.exists(mc._token_json_path(str(tmp_path)))


def test_delete_token_removes_entry(tmp_path, no_keyring):
    (tmp_path / "appdata").mkdir()
    mc.save_token(str(tmp_path), "a", "t1")
    mc.save_token(str(tmp_path), "b", "t2")
    mc.delete_token(str(tmp_path), "a")
    assert mc.load_token(str(tmp_path), "a") == ""
    assert mc.load_token(str(tmp_path), "b") == "t2"


# --------------------------------------------------------------------------- #
# tools cache store
# --------------------------------------------------------------------------- #
def test_save_and_get_server_tools(tmp_path):
    (tmp_path / "appdata").mkdir()
    tools = [{"name": "ping"}, {"name": "scan"}]
    mc.save_server_tools(str(tmp_path), "demo", tools)
    assert mc.get_server_tools(str(tmp_path), "demo") == tools


def test_load_tools_cache_missing_returns_empty(tmp_path):
    assert mc.load_tools_cache(str(tmp_path)) == {}


def test_get_server_tools_unknown_server_returns_empty(tmp_path):
    (tmp_path / "appdata").mkdir()
    mc.save_server_tools(str(tmp_path), "demo", [{"name": "ping"}])
    assert mc.get_server_tools(str(tmp_path), "other") == []


def test_delete_server_tools(tmp_path):
    (tmp_path / "appdata").mkdir()
    mc.save_server_tools(str(tmp_path), "demo", [{"name": "ping"}])
    mc.save_server_tools(str(tmp_path), "keep", [{"name": "x"}])
    mc.delete_server_tools(str(tmp_path), "demo")
    assert mc.get_server_tools(str(tmp_path), "demo") == []
    assert mc.get_server_tools(str(tmp_path), "keep") == [{"name": "x"}]
