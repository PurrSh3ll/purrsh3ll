"""Integration tests for the Phase-B bridge (purragent_core.graph.bridge).

These drive ``run_agent_graph`` end to end — the real LangGraph loop + the real
tool-dispatch logic — with ``_chat_stream`` monkeypatched to scripted responses
and a fake MCP manager. No network, no model, no real tools.
"""

import purragent_core.graph.bridge as bridge


class FakeMCP:
    """Minimal MCPManager stand-in with one callable tool."""

    def __init__(self):
        self.calls = []
        self._tool = {
            "name": "srv__run_command",
            "schema": {"type": "function",
                       "function": {"name": "srv__run_command", "parameters": {}}},
        }

    def all_tools(self):
        return [self._tool]

    def schema_for(self, name):
        return self._tool["schema"] if name == self._tool["name"] else None

    def call(self, name, args):
        self.calls.append((name, args))
        return {"text": f"ran {args.get('cmd', '')}"}


def _tc(cid, name, arguments):
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": arguments}}


def _patch_env(monkeypatch, responses):
    """Patch the bridge's injected helpers for a hermetic run."""
    it = iter(responses)

    def fake_chat_stream(endpoint, api_key, body, on_text, hide_thinking, on_activity=None):
        if on_activity:
            on_activity()
        return next(it)

    monkeypatch.setattr(bridge, "_chat_stream", fake_chat_stream)
    monkeypatch.setattr(bridge, "_openai_endpoint",
                        lambda profile, base_dir: ("http://x/v1/chat/completions", "k"))
    monkeypatch.setattr(bridge, "_get_retriever", lambda base_dir, all_tools: None)
    monkeypatch.setattr(bridge, "_model_context", lambda profile, base_dir: 8000)
    monkeypatch.setattr(bridge, "_tool_available", lambda t: True)


def test_run_agent_graph_tool_then_final(monkeypatch, tmp_path):
    (tmp_path / "appdata").mkdir()
    _patch_env(monkeypatch, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "the answer", "tool_calls": []},
    ])
    mcp = FakeMCP()
    events = []
    out = bridge.run_agent_graph(
        {"provider": "ollama", "model": "m"}, str(tmp_path), [],
        mcp, lambda *a: events.append(a), lambda *a: None, mode="auto")
    assert out == "the answer"
    assert mcp.calls == [("srv__run_command", {"cmd": "id"})]


def test_run_agent_graph_confirm_declined_skips_call(monkeypatch, tmp_path):
    (tmp_path / "appdata").mkdir()
    _patch_env(monkeypatch, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "rm -rf /"}')]},
        {"role": "assistant", "content": "ok, skipped", "tool_calls": []},
    ])
    # force the confirm gate on, then decline
    monkeypatch.setattr(bridge, "_needs_confirm", lambda mode, name, args: (True, "risky"))
    mcp = FakeMCP()
    out = bridge.run_agent_graph(
        {"provider": "ollama", "model": "m"}, str(tmp_path), [],
        mcp, lambda *a: None, lambda *a: None, mode="confirm",
        on_confirm=lambda name, args, reason: False)
    assert out == "ok, skipped"
    assert mcp.calls == []          # declined -> tool never ran


def test_run_agent_graph_dedup_repeated_call(monkeypatch, tmp_path):
    (tmp_path / "appdata").mkdir()
    # model calls the same tool with identical args twice, then answers
    _patch_env(monkeypatch, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("2", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "done", "tool_calls": []},
    ])
    mcp = FakeMCP()
    out = bridge.run_agent_graph(
        {"provider": "ollama", "model": "m"}, str(tmp_path), [],
        mcp, lambda *a: None, lambda *a: None, mode="auto")
    assert out == "done"
    # the identical second call is deduped -> mcp.call ran only once
    assert mcp.calls == [("srv__run_command", {"cmd": "id"})]


def test_run_agent_graph_direct_answer_no_tools(monkeypatch, tmp_path):
    (tmp_path / "appdata").mkdir()
    _patch_env(monkeypatch, [
        {"role": "assistant", "content": "just an answer", "tool_calls": []},
    ])
    mcp = FakeMCP()
    out = bridge.run_agent_graph(
        {"provider": "ollama", "model": "m"}, str(tmp_path), [],
        mcp, lambda *a: None, lambda *a: None, mode="auto")
    assert out == "just an answer"
    assert mcp.calls == []
