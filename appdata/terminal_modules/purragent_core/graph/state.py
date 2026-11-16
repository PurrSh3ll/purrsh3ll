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
    """State carried through the agent graph (JSON-serializable only)."""

    messages: Annotated[list, append_messages]  # full OpenAI-style transcript
    round: int                                   # completed call_model rounds this turn
    plan: list                                   # model's active update_plan steps
    final: Optional[str]                         # set once the model answers w/o tools
