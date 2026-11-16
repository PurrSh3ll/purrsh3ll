"""Equivalence tests: legacy loop vs LangGraph core produce the same behaviour.

Before dropping the legacy ``query_model_with_tools`` and flipping the default to
the graph, we prove the two paths are observationally equivalent: given the same
scripted model and the same fake MCP, they must yield the same final answer, the
same sequence of ``mcp.call`` invocations, the same ``on_event`` stream, and the
same *first request* sent to the model (which pins system-prompt + tools parity).

Both are driven with ``_chat_stream`` monkeypatched and a fake MCP — no network.
"""

import copy

import purragent_core.agent as legacy
import purragent_core.graph.integration as graph


class FakeMCP:
    def __init__(self):
        self.calls = []
        self._tools = [
            {"name": "srv__run_command",
             "schema": {"type": "function",
                        "function": {"name": "srv__run_command", "parameters": {}}}},
            {"name": "srv__read_file",
             "schema": {"type": "function",
                        "function": {"name": "srv__read_file", "parameters": {}}}},
        ]

    def all_tools(self):
        return list(self._tools)

    def schema_for(self, name):
        for t in self._tools:
            if t["name"] == name:
                return t["schema"]
        return None

    def call(self, name, args):
        self.calls.append((name, args))
        return {"text": f"out:{name}:{args.get('cmd', '')}"}


def _tc(cid, name, arguments):
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": arguments}}


def _run(mod, monkeypatch, script, *, mode="auto", on_confirm=None,
         needs_confirm_true=False, offer_hack=False):
    """Run one agent entry point (legacy or graph) under identical fakes."""
    bodies = []
    events = []
    hack = [0]
    it = iter(script)

    def fake_chat_stream(endpoint, api_key, body, on_text, hide_thinking, on_activity=None):
        if on_activity:
            on_activity()
        # snapshot: the legacy loop mutates its messages list in place across
        # rounds, so we must copy to capture the body as it was at this call.
        bodies.append(copy.deepcopy(body))
        return next(it)

    monkeypatch.setattr(mod, "_chat_stream", fake_chat_stream)
    monkeypatch.setattr(mod, "_openai_endpoint",
                        lambda p, b: ("http://x/v1/chat/completions", "k"))
    monkeypatch.setattr(mod, "_get_retriever", lambda b, t: None)
    monkeypatch.setattr(mod, "_model_context", lambda p, b: 8000)
    monkeypatch.setattr(mod, "_tool_available", lambda t: True)
    if needs_confirm_true:
        monkeypatch.setattr(mod, "_needs_confirm", lambda m, n, a: (True, "risky"))

    fn = legacy.query_model_with_tools if mod is legacy else graph.run_agent_graph
    mcp = FakeMCP()
    tmp = _run.tmp_path
    final = fn({"provider": "ollama", "model": "m"}, str(tmp), [], mcp,
               lambda *a: events.append(a), lambda *a: None,
               mode=mode, on_confirm=on_confirm, offer_hack=offer_hack,
               on_hack=(lambda: hack.__setitem__(0, hack[0] + 1)))
    return {"final": final, "calls": mcp.calls, "events": events, "hack": hack[0],
            "first_body": bodies[0] if bodies else None}


def _assert_equivalent(monkeypatch, tmp_path, script, **kw):
    _run.tmp_path = tmp_path
    (tmp_path / "appdata").mkdir(exist_ok=True)
    leg = _run(legacy, monkeypatch, list(script), **kw)
    gra = _run(graph, monkeypatch, list(script), **kw)
    assert leg["final"] == gra["final"], (leg["final"], gra["final"])
    assert leg["calls"] == gra["calls"], (leg["calls"], gra["calls"])
    assert leg["events"] == gra["events"], (leg["events"], gra["events"])
    assert leg["hack"] == gra["hack"], (leg["hack"], gra["hack"])
    # first request pins system-prompt + tools parity
    assert leg["first_body"] == gra["first_body"]
    return leg, gra


def test_equiv_tool_then_final(monkeypatch, tmp_path):
    _assert_equivalent(monkeypatch, tmp_path, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "the answer", "tool_calls": []},
    ])


def test_equiv_direct_answer(monkeypatch, tmp_path):
    _assert_equivalent(monkeypatch, tmp_path, [
        {"role": "assistant", "content": "no tools needed", "tool_calls": []},
    ])


def test_equiv_dedup_repeated_call(monkeypatch, tmp_path):
    _assert_equivalent(monkeypatch, tmp_path, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("2", "srv__run_command", '{"cmd": "id"}')]},
        {"role": "assistant", "content": "done", "tool_calls": []},
    ])


def test_equiv_confirm_declined(monkeypatch, tmp_path):
    _assert_equivalent(
        monkeypatch, tmp_path,
        [
            {"role": "assistant", "content": "",
             "tool_calls": [_tc("1", "srv__run_command", '{"cmd": "rm -rf /"}')]},
            {"role": "assistant", "content": "ok skipped", "tool_calls": []},
        ],
        mode="confirm", needs_confirm_true=True,
        on_confirm=lambda name, args, reason: False,
    )


def test_equiv_multi_tool_calls(monkeypatch, tmp_path):
    _assert_equivalent(monkeypatch, tmp_path, [
        {"role": "assistant", "content": "",
         "tool_calls": [_tc("a", "srv__run_command", '{"cmd": "id"}'),
                        _tc("b", "srv__read_file", '{"path": "/etc/passwd"}')]},
        {"role": "assistant", "content": "both ran", "tool_calls": []},
    ])


def test_equiv_enable_hacking_ends_turn(monkeypatch, tmp_path):
    # model proposes hacking mode -> on_hack fires once, turn ends, the
    # triggering assistant content is the final answer (same in both paths)
    leg, gra = _assert_equivalent(
        monkeypatch, tmp_path,
        [
            {"role": "assistant", "content": "switching to hacking mode",
             "tool_calls": [_tc("1", "enable_hacking_mode", '{"enable": true}')]},
        ],
        offer_hack=True,
    )
    assert leg["hack"] == 1
    assert leg["final"] == "switching to hacking mode"
    assert leg["calls"] == []
