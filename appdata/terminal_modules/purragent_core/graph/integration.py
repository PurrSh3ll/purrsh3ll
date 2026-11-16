"""purragent_core.graph.integration — adapter: real providers/tools <-> the graph.

The clean seam between the LangGraph core and purragent's domain. It turns the
existing streaming chat (``_chat_stream``) and tool dispatch (resolve +
``mcp.call`` + meta tools) into the two node callables the graph injects, and
exposes ``run_agent_graph`` — a drop-in for ``agent.query_model_with_tools`` with
the same signature — so the REPL can run the graph behind a flag.

Design (Phase-B step A — idiomatic state):
  * All turn state the agent reasons over — the growing ``active`` schema set,
    the ``seen`` dedup map, ``discovery_rounds`` and ``plan`` — lives in
    ``AgentState`` and flows through the nodes, so the turn is checkpointable and
    the nodes are transforms, not mutators of hidden context.
  * Only genuinely external resources are captured in these closures: the model
    endpoint/key, the MCP manager, the retriever, the stream callbacks, and two
    per-turn stream latches (first-token fired, trim-note shown). Nothing here
    holds agent state.
  * The live plan re-injection and transcript trimming are done on a LOCAL copy
    of the messages each round, so the checkpointed transcript stays append-only.

Not yet ported (the legacy loop still owns these; tracked for step B / later):
  * ``enable_hacking_mode`` hand-off — the flag path runs with ``offer_hack`` off;
  * resuming a half-finished tool turn from a checkpoint.
"""

import json
import os

import mcp_client
import psai

from purragent_core._shared import (
    DISCOVERY_MAX_ROUNDS, ENABLE_HACK_TOOL_NAME, MAX_ACTIVE_TOOLS, META_TOOL_NAME,
    PLAN_MAX_STEPS, PLAN_MODE_NOTE, PLANNED_MAX_ROUNDS, PURRAGENT_SYSTEM,
    RETRIEVE_TOP_N, SAVE_FINDING_TOOL_NAME, SAVE_MEMORY_TOOL_NAME,
    UPDATE_PLAN_TOOL_NAME, AGENT_TEMPERATURE, _DISCOVERY_GUIDE, _FINDING_GUIDE,
    _MEMORY_GUIDE, _META_TOOL, _PLAN_GUIDE, _SAVE_FINDING_TOOL, _SAVE_MEMORY_TOOL,
    _SEQUENCING_GUIDE, _UPDATE_PLAN_TOOL, _msgs_budget_chars, _needs_confirm,
    _trim_agent_msgs, console)
from purragent_core.models import _env_block, _model_context
from purragent_core.providers import _chat_stream, _openai_endpoint
from purragent_core.state import _add_finding, _add_memory, _delete_memory, _findings_block, _memory_block
from purragent_core.tools import _get_retriever, _resolve_tool_name, _tool_available
from purragent_core.ui import _StreamTrimmer, _render_plan

from purragent_core.graph.build import build_agent_graph

try:                                            # Text is only used for a status line
    from rich.text import Text
except Exception:                               # pragma: no cover
    Text = None


def graph_enabled() -> bool:
    """True when the LangGraph agent path is opted in via PURRAGENT_GRAPH."""
    return os.environ.get("PURRAGENT_GRAPH", "").strip().lower() in ("1", "true", "yes", "on")


def _make_model_caller(*, endpoint, api_key, model, temperature, custom_params,
                       hide_thinking, maxc, planning, offer_save, offer_plan,
                       offer_finding, discovery, trimmer, base_system,
                       plan_in_system, preamble_count, on_first_token):
    """Build the model_caller node callable (one streamed model turn).

    Reads the turn's tool scaffolding (``active`` / ``plan`` / ``discovery_rounds``)
    from state; captures only external resources and stream latches.
    """
    latch = {"first": False, "trim_noted": False}

    def _fire_first():
        if not latch["first"]:
            latch["first"] = True
            if on_first_token is not None:
                try:
                    on_first_token()
                except Exception:               # noqa: BLE001
                    pass

    def model_caller(state):
        messages = state.get("messages", [])
        active = state.get("active") or {}
        plan = state.get("plan") or []
        discovery_rounds = state.get("discovery_rounds", 0)

        # Work on a local copy so the checkpointed transcript stays append-only.
        send = list(messages)

        # Re-inject the live plan (sandwich): system slot on Anthropic, trailing
        # user message on OpenAI-compat.
        if plan:
            block = _render_plan(plan)
            if plan_in_system and send:
                send = [{**send[0], "content": base_system + "\n\n" + block}] + send[1:]
            else:
                send = send + [{"role": "user", "content": block}]
        elif plan_in_system and send and send[0].get("content") != base_system:
            send = [{**send[0], "content": base_system}] + send[1:]

        offer_meta = (not planning and discovery
                      and discovery_rounds < DISCOVERY_MAX_ROUNDS)
        tools_field = ([] if planning
                       else ([_META_TOOL] if offer_meta else [])
                       + ([_SAVE_MEMORY_TOOL] if offer_save else [])
                       + ([_UPDATE_PLAN_TOOL] if offer_plan else [])
                       + ([_SAVE_FINDING_TOOL] if offer_finding else [])
                       + list(active.values()))

        if _trim_agent_msgs(send, _msgs_budget_chars(maxc, tools_field),
                            preamble_count) and not latch["trim_noted"]:
            latch["trim_noted"] = True
            if Text is not None:
                console.print(Text("  ▸ trimmed earlier tool output to fit the "
                                   "context window", style="bright_black"))

        body = {"model": model, "messages": send}
        if tools_field:
            body["tools"] = tools_field
            body["tool_choice"] = "auto"
        if temperature is not None:
            body["temperature"] = temperature
        if custom_params:
            body.update(custom_params)

        message = _chat_stream(endpoint, api_key, body, trimmer.feed,
                               hide_thinking, on_activity=_fire_first)
        if message.get("tool_calls"):
            trimmer.end_turn()
        return message

    return model_caller


def _make_tool_runner(*, base_dir, mcp, all_tools, retriever, run_cmd,
                      on_event, on_confirm, mode):
    """Build the tool_runner node callable (execute one tool call).

    ``work`` is the node's mutable copy of the turn's tool scaffolding
    (``active`` / ``seen`` / ``discovery_rounds`` / ``plan``); branches mutate it
    and the node writes it back to state. Returns the tool-result message.
    """

    def _msg(call_id, content):
        return {"role": "tool", "tool_call_id": call_id, "content": content}

    def tool_runner(tc, work):
        fn = tc.get("function", {})
        name = fn.get("name", "")
        call_id = tc.get("id")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}

        active = work["active"]

        # ── request_tool: RAG discovery, grows the active schema set ───────────
        if name == META_TOOL_NAME:
            need = (args.get("need") or args.get("description") or "").strip()
            hits = retriever.retrieve(need, RETRIEVE_TOP_N) if retriever else []
            surfaced = []
            for hname, _score in hits:
                if hname not in active:
                    schema = mcp.schema_for(hname)
                    if schema is not None:
                        active[hname] = schema
                surfaced.append(mcp_client.split_namespaced(hname)[1])
            if not surfaced and run_cmd is not None:
                active.setdefault(run_cmd["name"], run_cmd["schema"])
                surfaced.append("run_command")
            while len(active) > MAX_ACTIVE_TOOLS:
                active.pop(next(iter(active)))
            work["discovery_rounds"] += 1
            on_event("search", need, {"hits": surfaced})
            if surfaced:
                ack = ("Matching tools now available to call: " + ", ".join(surfaced)
                       + ". Call one if it fits, or call request_tool again to refine.")
            else:
                ack = ("No matching tools were found. Try describing the need "
                       "differently, or answer without a tool.")
            return _msg(call_id, ack)

        # ── save_memory ───────────────────────────────────────────────────────
        if name == SAVE_MEMORY_TOOL_NAME:
            text = str(args.get("text") or "").strip()
            action = str(args.get("action") or "save").strip().lower()
            on_event("call", name, {"action": action, "text": text})
            if action == "delete":
                removed = _delete_memory(base_dir, text) if text else []
                ack = (f"Forgot {len(removed)} memory item(s). Done — do not call "
                       "save_memory again." if removed else
                       "Nothing matched to forget. Do not retry.")
            else:
                kind = str(args.get("kind") or "fact").strip().lower()
                saved = _add_memory(base_dir, text, kind) if text else False
                ack = ("Saved. It is stored and applies automatically from now on — "
                       "do NOT call save_memory again for this." if saved else
                       "Already stored — nothing to do. Do NOT save or delete it; "
                       "just continue answering.")
            on_event("result", name, {"text": ack})
            return _msg(call_id, ack)

        # ── update_plan (also raises the round ceiling via work["plan"]) ───────
        if name == UPDATE_PLAN_TOOL_NAME:
            raw = args.get("steps")
            steps = []
            if isinstance(raw, list):
                for s in raw[:PLAN_MAX_STEPS]:
                    if isinstance(s, dict) and str(s.get("text") or "").strip():
                        st = str(s.get("status") or "todo").strip().lower()
                        steps.append({"text": str(s["text"]).strip(),
                                      "status": st if st in ("todo", "doing", "done") else "todo"})
            work["plan"] = steps
            on_event("call", name,
                     {"steps": "; ".join(s["text"] for s in steps) or "(empty)"})
            if steps:
                done = sum(1 for s in steps if s["status"] == "done")
                ack = (f"Plan recorded ({done}/{len(steps)} done). It is shown to you "
                       "each turn — now DO the next step (call its tool). Call "
                       "update_plan again only to change a step's status, not to "
                       "restate the same plan.")
            else:
                ack = ("Empty plan ignored. Either answer directly or call update_plan "
                       "with real steps.")
            on_event("result", name, {"text": ack})
            return _msg(call_id, ack)

        # ── save_finding ───────────────────────────────────────────────────────
        if name == SAVE_FINDING_TOOL_NAME:
            ftext = str(args.get("finding") or "").strip()
            where = str(args.get("where") or "").strip()
            on_event("call", name, {"finding": (f"[{where}] " if where else "") + ftext})
            saved = _add_finding(base_dir, ftext, where) if ftext else False
            if saved:
                ack = ("Finding recorded — it is kept and shown to you on later turns "
                       "and in your final summary. Do not save it again; continue.")
            elif ftext:
                ack = ("Already recorded — nothing to do. Do not save it again; "
                       "continue with the task.")
            else:
                ack = "Empty finding ignored — nothing saved."
            on_event("result", name, {"text": ack})
            return _msg(call_id, ack)

        if name == ENABLE_HACK_TOOL_NAME:
            # The graph flag path runs with offer_hack off; /hack stays on legacy.
            return _msg(call_id, "Hacking mode was not enabled.")

        # ── resolve a fabricated / undiscovered tool name ─────────────────────
        if name not in active:
            resolved = _resolve_tool_name(name, all_tools)
            if resolved is None:
                on_event("result", name, {"text": f"unknown tool: {name}", "is_error": True})
                return _msg(call_id,
                            f"No tool named '{name}' exists. Tools are not called by "
                            "their description. Call request_tool with what you need, "
                            "then call the tool by the exact name provided.")
            if resolved not in active:
                active[resolved] = mcp.schema_for(resolved)
                while len(active) > MAX_ACTIVE_TOOLS:
                    active.pop(next(iter(active)))
            bare = mcp_client.split_namespaced(resolved)[1]
            if name in (resolved, bare):
                name = resolved
            else:
                on_event("search", name, {"hits": [bare]})
                return _msg(call_id,
                            f"'{name}' is not a callable tool name. The tool you want "
                            f"is now available as '{resolved}'. Call it using that exact "
                            "name and only its declared parameters (do not invent "
                            "argument names).")

        # ── per-turn dedup ─────────────────────────────────────────────────────
        key = name + ":" + json.dumps(args, sort_keys=True, default=str)
        if key in work["seen"]:
            return _msg(call_id,
                        "You already ran this exact call; its result was:\n"
                        + work["seen"][key] + "\nDo not repeat it — try different "
                        "arguments or another tool, or give your final answer.")

        # ── run-mode confirm gate ──────────────────────────────────────────────
        need, reason = _needs_confirm(mode, name, args)
        if need and on_confirm is not None and not on_confirm(name, args, reason):
            return _msg(call_id,
                        "The user declined to run this action. Do not retry it as-is; "
                        "propose an alternative or ask the user how to proceed.")

        on_event("call", name, args)
        result = mcp.call(name, args)
        on_event("result", name, result)
        text = result.get("text") or "(no output)"
        work["seen"][key] = text
        return _msg(call_id, text)

    return tool_runner


def run_agent_graph(profile: dict, base_dir: str, history: list,
                    mcp: "mcp_client.MCPManager", on_event, on_text,
                    mode: str = "auto", on_confirm=None,
                    offer_hack: bool = False, on_hack=None,
                    summary: str = "", recall: str = "",
                    max_context=None, on_first_token=None) -> str:
    """Drop-in replacement for query_model_with_tools, backed by the LangGraph core.

    Same signature and return contract: streams the answer via ``on_text`` and
    returns the final text. ``offer_hack`` / ``on_hack`` are accepted for
    signature parity but not acted on here (the flag path keeps /hack on legacy).
    """
    planning = (mode == "plan")
    model = profile.get("model", "")
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    temperature = AGENT_TEMPERATURE
    custom_params = psai._parse_custom_params(profile)
    custom_system = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    all_tools = [t for t in mcp.all_tools() if _tool_available(t)]
    retriever = _get_retriever(base_dir, all_tools)
    discovery = retriever is not None

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if planning:
        sys_parts.append(PLAN_MODE_NOTE)
    elif discovery:
        sys_parts += [_DISCOVERY_GUIDE]
    mem_block = _memory_block(base_dir)
    if mem_block:
        sys_parts.append(mem_block)
    if not planning:
        find_block = _findings_block(base_dir)
        if find_block:
            sys_parts.append(find_block)
    if summary:
        sys_parts.append("EARLIER CONVERSATION SUMMARY (older turns, condensed):\n" + summary)
    if recall:
        sys_parts.append(recall)
    if custom_system:
        sys_parts.append(custom_system)
    offer_save = not planning
    if offer_save:
        sys_parts.append(_MEMORY_GUIDE)
    offer_plan = not planning
    if offer_plan:
        sys_parts.append(_PLAN_GUIDE)
    offer_finding = not planning
    if offer_finding:
        sys_parts.append(_FINDING_GUIDE)
    if discovery:
        sys_parts.append(_SEQUENCING_GUIDE)

    messages = [{"role": "system", "content": "\n\n".join(sys_parts)}] + list(history)
    preamble_count = len(messages)
    base_system = messages[0]["content"]
    plan_in_system = endpoint.rstrip("/").endswith("/messages")
    maxc = max_context or _model_context(profile, base_dir)

    active = {} if discovery else {t["name"]: t["schema"] for t in all_tools}
    run_cmd = next((t for t in all_tools
                    if mcp_client.split_namespaced(t["name"])[1] == "run_command"), None)

    model_caller = _make_model_caller(
        endpoint=endpoint, api_key=api_key, model=model, temperature=temperature,
        custom_params=custom_params, hide_thinking=hide_thinking, maxc=maxc,
        planning=planning, offer_save=offer_save, offer_plan=offer_plan,
        offer_finding=offer_finding, discovery=discovery,
        trimmer=_StreamTrimmer(on_text), base_system=base_system,
        plan_in_system=plan_in_system, preamble_count=preamble_count,
        on_first_token=on_first_token)
    tool_runner = _make_tool_runner(
        base_dir=base_dir, mcp=mcp, all_tools=all_tools, retriever=retriever,
        run_cmd=run_cmd, on_event=on_event, on_confirm=on_confirm, mode=mode)

    app = build_agent_graph()
    out = app.invoke(
        {"messages": messages, "round": 0, "plan": [],
         "active": active, "seen": {}, "discovery_rounds": 0},
        config={
            "recursion_limit": 2 * PLANNED_MAX_ROUNDS + 5,
            "configurable": {"model_caller": model_caller, "tool_runner": tool_runner},
        },
    )
    final = out.get("final")
    if final is None:
        return ("[tool loop] stopped: reached the tool-call limit without a final "
                "answer.")
    return final
