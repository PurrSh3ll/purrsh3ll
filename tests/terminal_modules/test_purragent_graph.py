"""Tests for the Phase-B LangGraph agent core (purragent_core.graph).

These exercise the graph's control flow and guards with fake model/tool
callables — no LLM, no MCP, no network — plus real ``SqliteSaver``
checkpointing. The fakes stand in for the injected ``model_caller`` /
``tool_runner`` the integration layer supplies.
"""

import sqlite3

from purragent_core._shared import TOOL_LOOP_MAX_ROUNDS
from purragent_core.graph import guards
from purragent_core.graph.build import build_agent_graph


def _assistant(content="", tool_calls=None):
    return {"role": "assistant", "content": content, "tool_calls": tool_calls or []}


def _tool_call(cid, name="probe", args=None):
    return {"id": cid, "name": name, "args": args or {}}


def _scripted_model(responses):
    """model_caller that returns each scripted response in turn."""
    it = iter(responses)

    def model_caller(state):
        return next(it)

    return model_caller


def _echo_tool(tc, work):
    return {"role": "tool", "tool_call_id": tc.get("id"), "content": "ok"}


def _cfg(model_caller, tool_runner=_echo_tool, thread="t1"):
    return {"configurable": {
        "thread_id": thread,
        "model_caller": model_caller,
        "tool_runner": tool_runner,
    }}


# ── control flow ─────────────────────────────────────────────────────────────

def test_one_tool_round_then_final():
    """Model asks for a tool once, then answers: tool runs, loop ends."""
    model = _scripted_model([
        _assistant(tool_calls=[_tool_call("1")]),
        _assistant(content="all done"),
    ])
    app = build_agent_graph()
    out = app.invoke({"messages": [{"role": "user", "content": "hi"}], "round": 0},
                     config=_cfg(model))
    assert out["final"] == "all done"
    assert out["round"] == 2
    assert any(m.get("role") == "tool" and m.get("content") == "ok"
               for m in out["messages"])


def test_no_tools_finishes_immediately():
    model = _scripted_model([_assistant(content="direct answer")])
    app = build_agent_graph()
    out = app.invoke({"messages": [{"role": "user", "content": "hi"}], "round": 0},
                     config=_cfg(model))
    assert out["final"] == "direct answer"
    assert out["round"] == 1
    assert not any(m.get("role") == "tool" for m in out["messages"])


def test_multiple_tool_calls_in_one_round_all_execute():
    model = _scripted_model([
        _assistant(tool_calls=[_tool_call("a"), _tool_call("b"), _tool_call("c")]),
        _assistant(content="done"),
    ])
    app = build_agent_graph()
    out = app.invoke({"messages": [{"role": "user", "content": "hi"}], "round": 0},
                     config=_cfg(model))
    tool_ids = [m["tool_call_id"] for m in out["messages"] if m.get("role") == "tool"]
    assert tool_ids == ["a", "b", "c"]


# ── guards ───────────────────────────────────────────────────────────────────

def test_round_ceiling_stops_runaway():
    """A model that always wants a (distinct) tool is stopped at the ceiling."""
    def model(state):
        # distinct args each round -> loop-detector won't fire, so the round
        # ceiling is what must stop it
        return _assistant(tool_calls=[_tool_call("x", args={"i": state.get("round", 0)})])

    app = build_agent_graph()
    out = app.invoke(
        {"messages": [{"role": "user", "content": "go"}], "round": 0},
        config={**_cfg(model), "recursion_limit": 100},
    )
    assert out["round"] == TOOL_LOOP_MAX_ROUNDS


def test_loop_detection_stops_repeats():
    """Identical tool calls every round -> stop after the repeat threshold."""
    def model(state):
        return _assistant(tool_calls=[_tool_call("x", args={})])  # identical each time

    app = build_agent_graph()
    out = app.invoke({"messages": [{"role": "user", "content": "go"}], "round": 0},
                     config={**_cfg(model), "recursion_limit": 100})
    assistant_tool_rounds = [m for m in out["messages"]
                             if m.get("role") == "assistant" and m.get("tool_calls")]
    assert len(assistant_tool_rounds) == guards.LOOP_REPEAT_THRESHOLD


def test_guards_pure_functions():
    assert guards.max_rounds_reached({"round": TOOL_LOOP_MAX_ROUNDS}) is True
    assert guards.max_rounds_reached({"round": 0}) is False
    # a plan raises the ceiling
    assert guards.round_limit({"plan": [{"step": "x"}]}) > guards.round_limit({})
    same = [_assistant(tool_calls=[_tool_call("x", args={})]) for _ in range(3)]
    assert guards.detect_loop(same) is True
    varied = [_assistant(tool_calls=[_tool_call("x", args={"i": i})]) for i in range(3)]
    assert guards.detect_loop(varied) is False


# ── checkpointing ────────────────────────────────────────────────────────────

def test_sqlite_checkpoint_persists_final_state():
    from langgraph.checkpoint.sqlite import SqliteSaver

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    app = build_agent_graph(checkpointer=SqliteSaver(conn))
    model = _scripted_model([
        _assistant(tool_calls=[_tool_call("1")]),
        _assistant(content="persisted answer"),
    ])
    cfg = _cfg(model, thread="engagement-42")
    app.invoke({"messages": [{"role": "user", "content": "hi"}], "round": 0}, config=cfg)

    # a fresh read of the same thread returns the checkpointed state
    snap = app.get_state(cfg)
    assert snap.values["final"] == "persisted answer"
    assert snap.values["round"] == 2
    assert any(m.get("role") == "tool" for m in snap.values["messages"])
