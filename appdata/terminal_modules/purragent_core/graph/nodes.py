"""purragent_core.graph.nodes — the graph's node functions and router.

Nodes are transforms of ``AgentState``. The two leaf operations that touch the
outside world are injected via ``config["configurable"]`` (never stored in the
checkpointed state):

* ``model_caller(state) -> assistant_msg`` — one streamed model call; returns an
  OpenAI-style assistant dict, with ``tool_calls`` when the model wants to act.
* ``tool_runner(tool_call, work) -> tool_result_msg`` — execute one tool call;
  ``work`` is the node's mutable copy of the turn's tool scaffolding
  (``active`` / ``seen`` / ``discovery_rounds`` / ``plan``), seeded from state
  and written back as the node's state update.

Keeping those two as injected callables keeps the control flow (what the graph
*does*) testable with fakes, while the real providers/tools are supplied by the
integration layer.
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
    msg = model_caller(state)
    out = {"messages": [msg], "round": state.get("round", 0) + 1}
    if not msg.get("tool_calls"):
        out["final"] = (msg.get("content") or "").strip()
    return out


def exec_tools_node(state: dict, config=None) -> dict:
    """Execute every tool call in the latest assistant message.

    The tool scaffolding is pulled out of state into a mutable ``work`` copy,
    handed to ``tool_runner`` for each call (so discovery/dedup see within-round
    updates), then written back as the node's state update.
    """
    tool_runner = _deps(config)["tool_runner"]
    last = state["messages"][-1]
    work = {
        "active": dict(state.get("active") or {}),
        "seen": dict(state.get("seen") or {}),
        "discovery_rounds": state.get("discovery_rounds", 0),
        "plan": list(state.get("plan") or []),
        "halt": False,
    }
    results = [tool_runner(tc, work) for tc in (last.get("tool_calls") or [])]
    out = {
        "messages": results,
        "active": work["active"],
        "seen": work["seen"],
        "discovery_rounds": work["discovery_rounds"],
        "plan": work["plan"],
    }
    if work["halt"]:
        # a tool ended the turn (e.g. enable_hacking) — the triggering assistant
        # message's content stands as the final answer, matching the legacy loop.
        out["halt"] = True
        out["final"] = (last.get("content") or "").strip()
    return out


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


def route_after_tools(state: dict) -> str:
    """After running tools: end the turn if a tool halted it, else loop back."""
    if state.get("halt"):
        return END
    return "call_model"
