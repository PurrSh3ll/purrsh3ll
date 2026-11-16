"""purragent_core.graph.state — the typed, checkpointable agent state.

Messages are plain OpenAI-style dicts (the same shape the rest of purragent
uses):

    {"role": "system"|"user"|"assistant"|"tool", "content": str,
     "tool_calls": [ ... ]?, "tool_call_id": str?}

``messages`` uses an append reducer so every node that returns messages extends
the transcript instead of replacing it; the scalar channels (``round``,
``final``, ``plan``) are last-write-wins.
"""

from typing import Annotated, Optional, TypedDict


def append_messages(existing: Optional[list], new: Optional[list]) -> list:
    """Reducer: append new messages to the running transcript.

    Tolerates None on either side and a single dict passed instead of a list,
    so nodes can return ``{"messages": msg}`` or ``{"messages": [msg, ...]}``.
    """
    base = list(existing or [])
    if new is None:
        return base
    if isinstance(new, dict):
        new = [new]
    return base + list(new)


class AgentState(TypedDict, total=False):
    """State carried through the agent graph (JSON-serializable only).

    Everything the agent reasons over lives here — including the per-turn tool
    scaffolding (``active`` discovered schemas, the ``seen`` dedup map, the
    discovery-round counter) — so the whole turn is checkpointable and the nodes
    are transforms of state rather than mutators of hidden context. Only external
    resources (the model client, MCP, callbacks) are passed via config.
    """

    messages: Annotated[list, append_messages]  # full OpenAI-style transcript
    round: int                                   # completed call_model rounds this turn
    plan: list                                   # model's active update_plan steps
    final: Optional[str]                         # set once the model answers w/o tools
    active: dict                                  # tool name -> schema (grows via discovery)
    seen: dict                                    # dedup: call key -> prior result text
    discovery_rounds: int                        # request_tool calls used this turn
