"""purragent_core.graph.nodes — the graph's node functions and router.

Nodes pull their runtime dependencies from ``config["configurable"]`` (never
from the checkpointed state):

* ``model_caller(messages, state) -> assistant_msg`` — one streamed model call;
  returns an OpenAI-style assistant dict, with ``tool_calls`` when the model
  wants to act.
* ``tool_runner(tool_call, state) -> tool_result_msg`` — execute one tool call;
  returns an OpenAI-style ``{"role": "tool", ...}`` result.

This keeps the control flow (what the graph *does*) separate from the
integration (how a model/tool actually runs), so the flow is testable with
fakes and the real providers/tools are bridged in without touching this file.
"""

from langgraph.graph import END

from purragent_core.graph import guards


def _deps(config) -> dict:
    return (config or {}).get("configurable", {}) or {}


def call_model_node(state: dict, config=None) -> dict:
    """One model turn: call the model, append its message, bump the round.

    Sets ``final`` only when the model answered without requesting tools — that
    is the turn's terminal condition.
    """
    model_caller = _deps(config)["model_caller"]
    msg = model_caller(state.get("messages", []), state)
    out = {"messages": [msg], "round": state.get("round", 0) + 1}
    if not (msg.get("tool_calls")):
        out["final"] = (msg.get("content") or "").strip()
    return out


def exec_tools_node(state: dict, config=None) -> dict:
    """Execute every tool call in the latest assistant message."""
    tool_runner = _deps(config)["tool_runner"]
    last = state["messages"][-1]
    results = [tool_runner(tc, state) for tc in (last.get("tool_calls") or [])]
    return {"messages": results}


def route_after_model(state: dict) -> str:
    """Decide where to go after a model turn: run tools, or finish.

    Finish when the model asked for no tools, or when a guard says the loop has
    run long enough / is stuck (the model's partial answer stands as the result).
    """
    last = state["messages"][-1]
    if not last.get("tool_calls"):
        return END
    if guards.should_continue(state):
        return "tools"
    return END
