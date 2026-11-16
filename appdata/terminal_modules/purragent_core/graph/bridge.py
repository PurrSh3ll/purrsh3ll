"""purragent_core.graph.bridge — wire the real providers/tools into the graph.

This is the Phase-B step-2 integration layer. It turns purragent's existing
streaming chat (``_chat_stream``) and tool dispatch (resolve + ``mcp.call`` +
meta tools) into the two callables the graph's nodes expect
(``model_caller`` / ``tool_runner``), and exposes ``run_agent_graph`` — a
drop-in replacement for ``agent.query_model_with_tools`` with the same
signature, so the REPL can switch to the graph behind a flag.

What maps cleanly onto the graph (and is handled here):
  * the model turn (``_chat_stream``), with the live plan re-injected and the
    transcript trimmed to the window — done on a *local copy* each round, so the
    checkpointed state stays append-only;
  * tool dispatch: RAG discovery (``request_tool``), ``save_memory`` /
    ``update_plan`` / ``save_finding``, name resolution, per-turn dedup, the
    run-mode confirm gate, and ``mcp.call``.

Per-turn mutable scaffolding that is *not* JSON-serializable (the growing
``active`` tool-schema set, the ``seen`` dedup map, the discovery-round counter,
the stream trimmer) lives in a ``_TurnCtx`` passed through
``config["configurable"]`` — never in the checkpointed state.

Not yet ported (tracked for a later step; the legacy loop still owns these):
  * ``enable_hacking_mode`` hand-off — the flag path runs with ``offer_hack``
    off, so /hack stays on the legacy loop;
  * resuming a half-finished tool turn from a checkpoint (the ``_TurnCtx`` is
    rebuilt per invocation).
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


class _TurnCtx:
    """Non-serializable, per-turn scaffolding shared by the two node callables."""

    def __init__(self, *, active, discovery, retriever, run_cmd, trimmer,
                 preamble_count, base_system, plan_in_system):
        self.active = active                 # name -> schema (grows via discovery)
        self.discovery = discovery           # RAG discovery available?
        self.discovery_rounds = 0
        self.retriever = retriever
        self.run_cmd = run_cmd               # run_command fallback tool (or None)
        self.seen = {}                       # dedup: call key -> prior result text
        self.plan = []                       # active update_plan steps
        self.trimmer = trimmer
        self.preamble_count = preamble_count
        self.base_system = base_system
        self.plan_in_system = plan_in_system
        self.trim_noted = False
        self.first_fired = False


def _make_model_caller(*, ctx, endpoint, api_key, model, temperature, custom_params,
                       hide_thinking, maxc, planning, offer_save, offer_plan,
                       offer_finding, on_first_token):
    """Build the model_caller node callable (one streamed model turn)."""

    def _fire_first():
        if not ctx.first_fired:
            ctx.first_fired = True
            if on_first_token is not None:
                try:
                    on_first_token()
                except Exception:               # noqa: BLE001
                    pass

    def model_caller(messages, state):
        # Work on a local copy so the checkpointed transcript stays append-only.
        send = list(messages)

        # Re-inject the live plan (sandwich): system slot on Anthropic, trailing
        # user message on OpenAI-compat.
        if ctx.plan:
            block = _render_plan(ctx.plan)
            if ctx.plan_in_system and send:
                send = [{**send[0], "content": ctx.base_system + "\n\n" + block}] + send[1:]
            else:
                send = send + [{"role": "user", "content": block}]
        elif ctx.plan_in_system and send and send[0].get("content") != ctx.base_system:
            send = [{**send[0], "content": ctx.base_system}] + send[1:]

        offer_meta = (not planning and ctx.discovery
                      and ctx.discovery_rounds < DISCOVERY_MAX_ROUNDS)
        tools_field = ([] if planning
                       else ([_META_TOOL] if offer_meta else [])
                       + ([_SAVE_MEMORY_TOOL] if offer_save else [])
                       + ([_UPDATE_PLAN_TOOL] if offer_plan else [])
                       + ([_SAVE_FINDING_TOOL] if offer_finding else [])
                       + list(ctx.active.values()))

        # Trim this turn's growing tool transcript to fit the window (local copy).
        if _trim_agent_msgs(send, _msgs_budget_chars(maxc, tools_field),
                            ctx.preamble_count) and not ctx.trim_noted:
            ctx.trim_noted = True
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

        message = _chat_stream(endpoint, api_key, body, ctx.trimmer.feed,
                               hide_thinking, on_activity=_fire_first)
        if message.get("tool_calls"):
            ctx.trimmer.end_turn()
        return message

    return model_caller


def _make_tool_runner(*, ctx, base_dir, mcp, all_tools, on_event, on_confirm, mode):
    """Build the tool_runner node callable (execute one tool call)."""

    def _result(call_id, content, patch=None):
        msg = {"role": "tool", "tool_call_id": call_id, "content": content}
        return (msg, patch or {})

    def tool_runner(tc, state):
        fn = tc.get("function", {})
        name = fn.get("name", "")
        call_id = tc.get("id")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}

        # ── request_tool: RAG discovery, grows the active schema set ───────────
        if name == META_TOOL_NAME:
            need = (args.get("need") or args.get("description") or "").strip()
            hits = ctx.retriever.retrieve(need, RETRIEVE_TOP_N) if ctx.retriever else []
            surfaced = []
            for hname, _score in hits:
                if hname not in ctx.active:
                    schema = mcp.schema_for(hname)
                    if schema is not None:
                        ctx.active[hname] = schema
                surfaced.append(mcp_client.split_namespaced(hname)[1])
            if not surfaced and ctx.run_cmd is not None:
                ctx.active.setdefault(ctx.run_cmd["name"], ctx.run_cmd["schema"])
                surfaced.append("run_command")
            while len(ctx.active) > MAX_ACTIVE_TOOLS:
                ctx.active.pop(next(iter(ctx.active)))
            ctx.discovery_rounds += 1
            on_event("search", need, {"hits": surfaced})
            if surfaced:
                ack = ("Matching tools now available to call: " + ", ".join(surfaced)
                       + ". Call one if it fits, or call request_tool again to refine.")
            else:
                ack = ("No matching tools were found. Try describing the need "
                       "differently, or answer without a tool.")
            return _result(call_id, ack)

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
            return _result(call_id, ack)

        # ── update_plan (also raises the round ceiling via state["plan"]) ──────
        if name == UPDATE_PLAN_TOOL_NAME:
            raw = args.get("steps")
            steps = []
            if isinstance(raw, list):
                for s in raw[:PLAN_MAX_STEPS]:
                    if isinstance(s, dict) and str(s.get("text") or "").strip():
                        st = str(s.get("status") or "todo").strip().lower()
                        steps.append({"text": str(s["text"]).strip(),
                                      "status": st if st in ("todo", "doing", "done") else "todo"})
            ctx.plan = steps
            on_event("call", name,
                     {"steps": "; ".join(s["text"] for s in ctx.plan) or "(empty)"})
            if ctx.plan:
                done = sum(1 for s in ctx.plan if s["status"] == "done")
                ack = (f"Plan recorded ({done}/{len(ctx.plan)} done). It is shown to you "
                       "each turn — now DO the next step (call its tool). Call "
                       "update_plan again only to change a step's status, not to "
                       "restate the same plan.")
            else:
                ack = ("Empty plan ignored. Either answer directly or call update_plan "
                       "with real steps.")
            on_event("result", name, {"text": ack})
            return _result(call_id, ack, {"plan": ctx.plan})

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
            return _result(call_id, ack)

        if name == ENABLE_HACK_TOOL_NAME:
            # The graph flag path runs with offer_hack off; /hack stays on legacy.
            return _result(call_id, "Hacking mode was not enabled.")

        # ── resolve a fabricated / undiscovered tool name ─────────────────────
        if name not in ctx.active:
            resolved = _resolve_tool_name(name, all_tools)
            if resolved is None:
                on_event("result", name, {"text": f"unknown tool: {name}", "is_error": True})
                return _result(call_id,
                               f"No tool named '{name}' exists. Tools are not called by "
                               "their description. Call request_tool with what you need, "
                               "then call the tool by the exact name provided.")
            if resolved not in ctx.active:
                ctx.active[resolved] = mcp.schema_for(resolved)
                while len(ctx.active) > MAX_ACTIVE_TOOLS:
                    ctx.active.pop(next(iter(ctx.active)))
            bare = mcp_client.split_namespaced(resolved)[1]
            if name in (resolved, bare):
                name = resolved
            else:
                on_event("search", name, {"hits": [bare]})
                return _result(call_id,
                               f"'{name}' is not a callable tool name. The tool you want "
                               f"is now available as '{resolved}'. Call it using that exact "
                               "name and only its declared parameters (do not invent "
                               "argument names).")

        # ── per-turn dedup ─────────────────────────────────────────────────────
        key = name + ":" + json.dumps(args, sort_keys=True, default=str)
        if key in ctx.seen:
            return _result(call_id,
                           "You already ran this exact call; its result was:\n"
                           + ctx.seen[key] + "\nDo not repeat it — try different "
                           "arguments or another tool, or give your final answer.")

        # ── run-mode confirm gate ──────────────────────────────────────────────
        need, reason = _needs_confirm(mode, name, args)
        if need and on_confirm is not None and not on_confirm(name, args, reason):
            return _result(call_id,
                           "The user declined to run this action. Do not retry it as-is; "
                           "propose an alternative or ask the user how to proceed.")

        on_event("call", name, args)
        result = mcp.call(name, args)
        on_event("result", name, result)
        text = result.get("text") or "(no output)"
        ctx.seen[key] = text
        return _result(call_id, text)

    return tool_runner


def run_agent_graph(profile: dict, base_dir: str, history: list,
                    mcp: "mcp_client.MCPManager", on_event, on_text,
                    mode: str = "auto", on_confirm=None,
                    offer_hack: bool = False, on_hack=None,
                    summary: str = "", recall: str = "",
                    max_context=None, on_first_token=None) -> str:
    """Drop-in replacement for query_model_with_tools, backed by the LangGraph core.

    Same signature and return contract: streams the answer via ``on_text`` and
    returns the final text. ``offer_hack``/``on_hack`` are accepted for
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

    ctx = _TurnCtx(active=active, discovery=discovery, retriever=retriever,
                   run_cmd=run_cmd, trimmer=_StreamTrimmer(on_text),
                   preamble_count=preamble_count, base_system=base_system,
                   plan_in_system=plan_in_system)

    model_caller = _make_model_caller(
        ctx=ctx, endpoint=endpoint, api_key=api_key, model=model,
        temperature=temperature, custom_params=custom_params,
        hide_thinking=hide_thinking, maxc=maxc, planning=planning,
        offer_save=offer_save, offer_plan=offer_plan, offer_finding=offer_finding,
        on_first_token=on_first_token)
    tool_runner = _make_tool_runner(
        ctx=ctx, base_dir=base_dir, mcp=mcp, all_tools=all_tools,
        on_event=on_event, on_confirm=on_confirm, mode=mode)

    app = build_agent_graph()
    out = app.invoke(
        {"messages": messages, "round": 0, "plan": []},
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
