"""purragent_core.graph.guards — pure loop guards for the agent graph.

These mirror the ceilings the legacy ``query_model_with_tools`` loop enforced:

* **round ceiling** — ``TOOL_LOOP_MAX_ROUNDS`` normally, raised to
  ``PLANNED_MAX_ROUNDS`` once the model has an active ``update_plan`` (so a
  genuinely multi-step task gets more room than a plain chat turn);
* **loop detection** — stop if the model emits the same tool call(s) several
  rounds running, which means it is stuck rather than making progress.

Every function here is pure (state in, bool out) so it unit-tests without a
model, an LLM, or any I/O.
"""

import json

from purragent_core._shared import PLANNED_MAX_ROUNDS, TOOL_LOOP_MAX_ROUNDS

# How many identical consecutive tool-call rounds count as "stuck".
LOOP_REPEAT_THRESHOLD = 3


def round_limit(state: dict) -> int:
    """Round ceiling for this turn (raised once a plan is active)."""
    return PLANNED_MAX_ROUNDS if state.get("plan") else TOOL_LOOP_MAX_ROUNDS


def max_rounds_reached(state: dict) -> bool:
    """True once the turn has used its whole round budget."""
    return state.get("round", 0) >= round_limit(state)


def _tool_call_signature(msg: dict) -> str:
    """Stable signature of a message's tool calls (name + args), shape-agnostic.

    Handles both purragent's internal tool-call shape ``{"name", "args"}`` and
    the raw OpenAI shape ``{"function": {"name", "arguments"}}``.
    """
    sig = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        name = tc.get("name") or fn.get("name") or ""
        args = tc.get("args")
        if args is None:
            args = fn.get("arguments")
        try:
            args_norm = json.dumps(args, sort_keys=True, default=str)
        except TypeError:
            args_norm = str(args)
        sig.append((name, args_norm))
    return json.dumps(sig, sort_keys=True)


def detect_loop(messages: list, repeats: int = LOOP_REPEAT_THRESHOLD) -> bool:
    """True if the last ``repeats`` tool-calling rounds are identical."""
    sigs = [
        _tool_call_signature(m)
        for m in (messages or [])
        if m.get("role") == "assistant" and m.get("tool_calls")
    ]
    if len(sigs) < repeats:
        return False
    return len(set(sigs[-repeats:])) == 1


def should_continue(state: dict) -> bool:
    """Whether the loop may run another tool round."""
    return not max_rounds_reached(state) and not detect_loop(state.get("messages", []))
