"""purragent_core.agent — extracted from monolithic purragent.py (Phase A refactor)."""

from rich.text import Text
import conv_memory
import json
import mcp_client
import os
import psai

from purragent_core._shared import (AGENT_TEMPERATURE, AGENT_TURN_MAX_SECONDS, DISCOVERY_MAX_ROUNDS, ENABLE_HACK_TOOL_NAME, MAX_ACTIVE_TOOLS, MEMORY_LOOKUP_TOKENS, META_TOOL_NAME, PLANNED_MAX_ROUNDS, PLAN_MAX_STEPS, PLAN_MODE_NOTE, PURRAGENT_SYSTEM, RETRIEVE_TOP_N, SAVE_FINDING_TOOL_NAME, SAVE_MEMORY_TOOL_NAME, TOOL_LOOP_MAX_ROUNDS, UPDATE_PLAN_TOOL_NAME, _DISCOVERY_GUIDE, _ENABLE_HACK_TOOL, _FINDING_GUIDE, _HACK_TRIGGER_GUIDE, _MEMORY_GUIDE, _META_TOOL, _PLAN_GUIDE, _SAVE_FINDING_TOOL, _SAVE_MEMORY_TOOL, _SEQUENCING_GUIDE, _SUMMARY_SYSTEM, _UPDATE_PLAN_TOOL, _msgs_budget_chars, _needs_confirm, _trim_agent_msgs, console)
from purragent_core.models import (_conv_budget, _env_block, _model_context)
from purragent_core.providers import (_chat_stream, _openai_endpoint)
from purragent_core.state import (_add_finding, _add_memory, _delete_memory, _findings_block, _memory_block)
from purragent_core.tools import (_catalog_block, _get_retriever, _resolve_tool_name, _tool_available)
from purragent_core.ui import (_StreamTrimmer, _render_plan)

def _summarize_turns(profile: dict, base_dir: str, existing: str, turns: list,
                     cap_chars: int):
    """Fold `turns` (and the existing summary) into an updated summary via one tool-free
    LLM call, hard-capped at cap_chars. Returns None on failure/empty (caller then keeps
    the old summary and history, and retries next turn) so context is never lost."""
    convo = "\n".join(f"{m.get('role', '?')}: {m.get('content', '')}" for m in turns
                      if isinstance(m.get("content"), str) and m.get("content").strip())
    if not convo.strip():
        return None
    words = max(120, cap_chars // 6)
    user = ("EXISTING SUMMARY:\n" + (existing or "(none)")
            + "\n\nOLDER TURNS to fold in:\n" + convo
            + f"\n\nReturn the updated summary (under ~{words} words).")
    body = {"model": profile.get("model", ""),
            "messages": [{"role": "system", "content": _SUMMARY_SYSTEM},
                         {"role": "user", "content": user}],
            "temperature": AGENT_TEMPERATURE}
    custom = psai._parse_custom_params(profile)
    if custom:
        body.update(custom)
    try:
        endpoint, api_key = _openai_endpoint(profile, base_dir)
        parts: list = []
        _chat_stream(endpoint, api_key, body, lambda t: parts.append(t),
                     hide_thinking=True, render_reasoning=False,
                     max_seconds=AGENT_TURN_MAX_SECONDS)
    except Exception:                                  # noqa: BLE001
        return None
    out = "".join(parts).strip()
    return out[:cap_chars] if out else None



def _maybe_summarize(profile: dict, base_dir: str, ctx: dict, mcp, mode: str,
                     history: list) -> None:
    """Keep the verbatim history within its budget: summarise + drop the oldest turns
    that overflow. Mutates `history` in place and updates ctx['summary']. No-op without a
    model, in plan mode, or when the window is unknown / the history still fits."""
    if not profile or mode == "plan":
        return
    budget = _conv_budget(profile, base_dir, ctx, mcp, mode)
    if budget is None:
        return
    avail, recent_target, summ_cap = budget
    if avail <= 0:
        return
    hist_chars = sum(len(m.get("content") or "") for m in history
                     if isinstance(m.get("content"), str))
    if hist_chars <= avail:
        return                                         # fits — recent borrows summary's
                                                       # idle space (matches /context)
    # Overflowed the pool: keep the newest turns within recent_target, summarise the rest.
    total, keep_from = 0, len(history)
    for i in range(len(history) - 1, -1, -1):
        c = len(history[i].get("content") or "") \
            if isinstance(history[i].get("content"), str) else 0
        if total + c > recent_target and i < len(history) - 1:
            break                                      # always keep at least the last turn
        total += c
        keep_from = i
    overflow = history[:keep_from]
    if not overflow:
        return
    new_summary = _summarize_turns(profile, base_dir, ctx.get("summary", ""),
                                   overflow, summ_cap)
    if new_summary:
        ctx["summary"] = new_summary
        history[:] = history[keep_from:]               # drop the summarised turns
        console.print(Text(f"  ▸ condensed {len(overflow)} older turn(s) into the "
                           "summary (keeping the window in budget)",
                           style="bright_black"))



def _memory_lookup_enabled(base_dir: str) -> bool:
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json")) as f:
            v = (json.load(f).get("purragent") or {}).get("memory_lookup")
        return True if v is None else bool(v)
    except Exception:                                  # noqa: BLE001
        return True



def _conv_mem(ctx: dict, base_dir: str):
    cm = ctx.get("conv_mem")
    if cm is None:
        cm = conv_memory.ConversationMemory(base_dir)
        ctx["conv_mem"] = cm
    return cm



def _remember_exchange(ctx: dict, base_dir: str, user_text: str,
                       assistant_text: str) -> None:
    """Index one completed exchange for future recall (no-op if disabled/unavailable)."""
    if not _memory_lookup_enabled(base_dir) or not (user_text or "").strip():
        return
    try:
        _conv_mem(ctx, base_dir).add(user_text, assistant_text,
                                     ctx.get("session_id", "?"))
    except Exception:                                  # noqa: BLE001
        pass



def _maybe_recall(ctx: dict, base_dir: str, history: list) -> str:
    """Recall relevant past exchanges for the latest user turn, fitted to the reserved
    memory-lookup slot. Returns the injectable block, or '' (disabled / nothing / no
    embedder). Excludes exchanges whose user turn is still verbatim in `history`."""
    if not _memory_lookup_enabled(base_dir):
        return ""
    query = next((m.get("content") or "" for m in reversed(history)
                  if m.get("role") == "user"), "")
    if not query.strip():
        return ""
    recent_users = {m.get("content") for m in history if m.get("role") == "user"}
    try:
        hits = _conv_mem(ctx, base_dir).recall(query, recent_users, top_k=8)
    except Exception:                                  # noqa: BLE001
        return ""
    budget = MEMORY_LOOKUP_TOKENS * 4
    lines, used = [], 0
    for text, _score in hits:
        one = "- " + " ".join(text.split())            # flatten whitespace
        if used + len(one) > budget:
            break
        lines.append(one)
        used += len(one)
    ctx["recall_chars"] = used                         # for /context display
    if not lines:
        return ""
    return ("RECALLED EARLIER CONTEXT (semantically relevant past turns / sessions):\n"
            + "\n".join(lines))



def query_model_with_tools(profile: dict, base_dir: str, history: list,
                           mcp: "mcp_client.MCPManager", on_event, on_text,
                           mode: str = "auto", on_confirm=None,
                           offer_hack: bool = False, on_hack=None,
                           summary: str = "", recall: str = "",
                           max_context=None, on_first_token=None) -> str:
    """Run the agent loop and return the model's final text answer.

    `on_event(kind, name, payload)` reports progress: kind is 'call' (payload is
    the arguments dict), 'result' (payload is the MCP result dict), or 'search'
    (a request_tool discovery — payload is {'need', 'hits'}).
    `on_text(piece)` receives streamed answer chunks as they arrive (the final
    answer is streamed live, so the caller should not print the return value).
    `mode` is the run mode: 'plan' (no tools, just plan), 'auto', 'confirm', or
    'semi-auto'. `on_confirm(name, args, reason) -> bool` is asked before a tool
    call the mode flags as needing approval; returning False skips it.
    `offer_hack` adds the enable_hacking_mode tool (only when hacking is off); if
    the model calls it with enable=true, `on_hack()` is invoked and the turn ends
    so the caller can run the /hack flow.
    `max_context` is the effective window (honouring /setcontext); when omitted it
    falls back to the model's advertised window. Used to trim this turn's tool
    transcript if it overflows.
    """
    planning = (mode == "plan")
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    endpoint, api_key = _openai_endpoint(profile, base_dir)
    temperature   = AGENT_TEMPERATURE      # pinned; not inherited from the profile
    custom_params = psai._parse_custom_params(profile)
    custom_system = profile.get("custom_system", "").strip()
    hide_thinking = bool(profile.get("hide_thinking", False))

    # Only offer tools that can actually run here — a tool whose program/library isn't
    # installed would only return '[not installed]' and waste the call.
    all_tools = [t for t in mcp.all_tools() if _tool_available(t)]
    retriever = _get_retriever(base_dir, all_tools)
    discovery = retriever is not None      # False → fall back to sending all schemas

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if planning:
        sys_parts.append(PLAN_MODE_NOTE)
    elif discovery:
        sys_parts += [_DISCOVERY_GUIDE, _catalog_block(all_tools)]
    if offer_hack and not planning:
        sys_parts.append(_HACK_TRIGGER_GUIDE)
    mem_block = _memory_block(base_dir)                 # remembered instructions + facts
    if mem_block:
        sys_parts.append(mem_block)
    if not planning:
        find_block = _findings_block(base_dir)          # facts the model discovered before
        if find_block:
            sys_parts.append(find_block)
    if summary:                                         # condensed older conversation
        sys_parts.append("EARLIER CONVERSATION SUMMARY (older turns, condensed):\n"
                         + summary)
    if recall:                                          # semantically recalled past turns
        sys_parts.append(recall)
    if custom_system:
        sys_parts.append(custom_system)
    offer_save = not planning              # always available (except in plan mode)
    if offer_save:
        sys_parts.append(_MEMORY_GUIDE)    # nudge weaker models to actually save
    offer_plan = not planning              # multi-step to-do tracking (model decides when)
    if offer_plan:
        sys_parts.append(_PLAN_GUIDE)
    offer_finding = not planning           # record concrete discoveries about the target
    if offer_finding:
        sys_parts.append(_FINDING_GUIDE)
    if discovery:                          # tools are on → keep run-then-save ordered
        sys_parts.append(_SEQUENCING_GUIDE)   # stop weak models writing empty placeholder files
    # Local working copy of the transcript: the raw assistant tool-call messages
    # and tool results live only here, not in the caller's plain history.
    msgs = [{"role": "system", "content": "\n\n".join(sys_parts)}] + list(history)
    # Everything up to here (system + the caller's conversation) is the untouchable
    # preamble; tool-call groups appended during THIS turn's loop are what we trim if
    # they pile up past the window (the pre-flight guard only checks the pre-turn size).
    preamble = len(msgs)
    maxc = max_context or _model_context(profile, base_dir)
    trim_noted = False

    # Accumulating set of full schemas the model may call. In discovery mode it
    # starts empty and grows as request_tool surfaces tools; in fallback mode it
    # holds every tool up front (classic behaviour).
    active: dict = {} if discovery else {t["name"]: t["schema"] for t in all_tools}
    discovery_rounds = 0
    trimmer = _StreamTrimmer(on_text)   # swallow the blank lines around tool calls
    # The universal escape hatch, handed over only when a discovery round finds
    # nothing — so the model still prefers the safer specialised tools, but is
    # never stranded when RAG can't match its need.
    run_cmd = next((t for t in all_tools
                    if mcp_client.split_namespaced(t["name"])[1] == "run_command"),
                   None)
    seen: dict = {}   # (tool name + canonical args) -> prior result text, for dedup
    plan: list = []           # the model's current update_plan steps (this turn only)
    plan_msg = None           # trailing plan reminder we re-inject (OpenAI-compat path)
    base_system = msgs[0]["content"]      # system content without the live-plan block
    # Anthropic groups tool results into a user turn, so a trailing user plan message
    # would produce two user turns in a row — fold the plan into the system slot there.
    plan_in_system = endpoint.rstrip("/").endswith("/messages")

    # Fire on_first_token exactly once, on the model's first streamed byte — the REPL
    # uses it to drop the "warming up" spinner shown during retriever build + TTFT.
    _first = {"done": False}
    def _fire_first():
        if not _first["done"]:
            _first["done"] = True
            if on_first_token is not None:
                try:
                    on_first_token()
                except Exception:                          # noqa: BLE001
                    pass

    _round = 0
    while _round < (PLANNED_MAX_ROUNDS if plan else TOOL_LOOP_MAX_ROUNDS):
        _round += 1
        offer_meta = (not planning and discovery
                      and discovery_rounds < DISCOVERY_MAX_ROUNDS)
        tools_field = ([] if planning
                       else ([_META_TOOL] if offer_meta else [])
                       + ([_ENABLE_HACK_TOOL] if offer_hack else [])
                       + ([_SAVE_MEMORY_TOOL] if offer_save else [])
                       + ([_UPDATE_PLAN_TOOL] if offer_plan else [])
                       + ([_SAVE_FINDING_TOOL] if offer_finding else [])
                       + list(active.values()))

        # Keep this turn's growing transcript within the window: tool results pile up
        # across rounds with no summariser here (the pre-flight guard only sizes the
        # pre-turn history). Trim oldest tool groups; tell the user once per turn.
        if _trim_agent_msgs(msgs, _msgs_budget_chars(maxc, tools_field), preamble) \
                and not trim_noted:
            trim_noted = True
            console.print(Text("  ▸ trimmed earlier tool output to fit the context "
                               "window", style="bright_black"))

        # Re-inject the live plan each round so it stays in view (weak models lose the
        # thread mid-task). Sandwich: the policy rides in the system slot up top; the
        # working checklist goes as close to the model's next decision as the wire
        # format allows — a trailing user message (recency) on OpenAI-compat, folded
        # into the system slot on Anthropic. Kept to a single, always-current copy.
        if plan_msg is not None and plan_msg in msgs:
            msgs.remove(plan_msg)
            plan_msg = None
        if plan:
            block = _render_plan(plan)
            if plan_in_system:
                msgs[0]["content"] = base_system + "\n\n" + block
            else:
                plan_msg = {"role": "user", "content": block}
                msgs.append(plan_msg)
        elif plan_in_system and msgs[0]["content"] != base_system:
            msgs[0]["content"] = base_system

        body = {"model": model, "messages": msgs}
        if tools_field:
            body["tools"] = tools_field
            body["tool_choice"] = "auto"
        if temperature is not None:
            body["temperature"] = temperature
        if custom_params:
            body.update(custom_params)

        message = _chat_stream(endpoint, api_key, body, trimmer.feed, hide_thinking,
                               on_activity=_fire_first)

        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return (message.get("content") or "").strip()

        # A tool-call turn — discard its trailing whitespace so no blank lines
        # land between the streamed text and the tool-activity lines.
        trimmer.end_turn()
        # Keep the assistant's tool-call turn in context, then answer each call.
        msgs.append(message)
        for tc in tool_calls:
            fn   = tc.get("function", {})
            name = fn.get("name", "")
            call_id = tc.get("id")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            if name == META_TOOL_NAME:
                # Discovery: retrieve tools matching the described need and add
                # their schemas to the active set (poprawka 1 — they persist).
                need = (args.get("need") or args.get("description") or "").strip()
                hits = retriever.retrieve(need, RETRIEVE_TOP_N) if retriever else []
                surfaced = []
                for hname, _score in hits:
                    if hname not in active:
                        schema = mcp.schema_for(hname)
                        if schema is not None:
                            active[hname] = schema
                    surfaced.append(mcp_client.split_namespaced(hname)[1])
                # Nothing matched — surface run_command as a fallback so the model
                # can still act (via a shell command) instead of getting stuck.
                if not surfaced and run_cmd is not None:
                    if run_cmd["name"] not in active:
                        active[run_cmd["name"]] = run_cmd["schema"]
                    surfaced.append("run_command")
                # Bound the context: drop the oldest schemas past the cap.
                while len(active) > MAX_ACTIVE_TOOLS:
                    active.pop(next(iter(active)))
                discovery_rounds += 1
                on_event("search", need, {"hits": surfaced})
                if surfaced:
                    ack = ("Matching tools now available to call: "
                           + ", ".join(surfaced) + ". Call one if it fits, or "
                           "call request_tool again to refine.")
                else:
                    ack = ("No matching tools were found. Try describing the need "
                           "differently, or answer without a tool.")
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": ack})
                continue

            if name == SAVE_MEMORY_TOOL_NAME:
                text = str(args.get("text") or "").strip()
                action = str(args.get("action") or "save").strip().lower()
                on_event("call", name, {"action": action, "text": text})
                # Acks steer the model to STOP — weak models otherwise re-save / delete /
                # re-save in a loop (the normal tool loop has no dedup).
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
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": ack})
                continue

            if name == UPDATE_PLAN_TOOL_NAME:
                # Replace the whole plan (not a delta). Keep only well-formed steps and
                # cap the length so a weak model can't sprawl. The plan is re-injected
                # each round by the sandwich block above; here we just store it + ack.
                raw = args.get("steps")
                steps = []
                if isinstance(raw, list):
                    for s in raw[:PLAN_MAX_STEPS]:
                        if isinstance(s, dict) and str(s.get("text") or "").strip():
                            st = str(s.get("status") or "todo").strip().lower()
                            steps.append({"text": str(s["text"]).strip(),
                                          "status": st if st in
                                          ("todo", "doing", "done") else "todo"})
                plan = steps                       # raises the round cap once non-empty
                on_event("call", name,
                         {"steps": "; ".join(s["text"] for s in plan) or "(empty)"})
                if plan:
                    done = sum(1 for s in plan if s["status"] == "done")
                    ack = (f"Plan recorded ({done}/{len(plan)} done). It is shown to you "
                           "each turn — now DO the next step (call its tool). Call "
                           "update_plan again only to change a step's status, not to "
                           "restate the same plan.")
                else:
                    ack = ("Empty plan ignored. Either answer directly or call "
                           "update_plan with real steps.")
                on_event("result", name, {"text": ack})
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": ack})
                continue

            if name == SAVE_FINDING_TOOL_NAME:
                ftext = str(args.get("finding") or "").strip()
                where = str(args.get("where") or "").strip()
                on_event("call", name,
                         {"finding": (f"[{where}] " if where else "") + ftext})
                saved = _add_finding(base_dir, ftext, where) if ftext else False
                # Ack steers the model to STOP re-saving (the loop has dedup, but the ack
                # keeps weak models from re-recording the same fact).
                if saved:
                    ack = ("Finding recorded — it is kept and shown to you on later turns "
                           "and in your final summary. Do not save it again; continue.")
                elif ftext:
                    ack = ("Already recorded — nothing to do. Do not save it again; "
                           "continue with the task.")
                else:
                    ack = "Empty finding ignored — nothing saved."
                on_event("result", name, {"text": ack})
                msgs.append({"role": "tool", "tool_call_id": call_id, "content": ack})
                continue

            if name == ENABLE_HACK_TOOL_NAME:
                # Model proposes hacking mode. Hand control to the /hack flow (same
                # as if the user typed /hack): signal the caller and end the turn —
                # the REPL then runs the confirm + announcement. enable=false (or no
                # handler) is a no-op the model can keep going from.
                if bool(args.get("enable")) and on_hack is not None:
                    on_hack()
                    return (message.get("content") or "").strip()
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": "Hacking mode was not enabled."})
                continue

            # Robustness: some models ignore request_tool and fabricate a call
            # using a catalog line (the tool's description) or an undiscovered
            # name. Routing that straight to mcp.call fails cryptically ("no such
            # MCP server: None"), which models then misread as a server outage.
            if name not in active:
                resolved = _resolve_tool_name(name, all_tools)
                if resolved is None:
                    on_event("result", name, {"text": f"unknown tool: {name}",
                                              "is_error": True})
                    msgs.append({"role": "tool", "tool_call_id": call_id,
                                 "content": (
                                     f"No tool named '{name}' exists. Tools are not "
                                     "called by their description. Call request_tool "
                                     "with what you need, then call the tool by the "
                                     "exact name provided.")})
                    continue
                if resolved not in active:
                    active[resolved] = mcp.schema_for(resolved)
                    while len(active) > MAX_ACTIVE_TOOLS:
                        active.pop(next(iter(active)))
                bare = mcp_client.split_namespaced(resolved)[1]
                if name in (resolved, bare):
                    name = resolved          # real name, loose form — run it below
                else:
                    # Called by description: the arguments are likely fabricated
                    # too, so surface the real tool and ask for a clean retry.
                    on_event("search", name, {"hits": [bare]})
                    msgs.append({"role": "tool", "tool_call_id": call_id,
                                 "content": (
                                     f"'{name}' is not a callable tool name. The tool "
                                     f"you want is now available as '{resolved}'. Call "
                                     "it using that exact name and only its declared "
                                     "parameters (do not invent argument names).")})
                    continue

            # Skip a call the model has already run verbatim this turn: weak models
            # otherwise re-issue an identical call and burn rounds. Feed back the prior
            # result and steer them elsewhere (the hacktools agent has the same guard).
            # Meta/control tools (request_tool, save_memory, enable_hacking_mode) never
            # reach here — they 'continue' above — so dedup only covers real MCP calls.
            key = name + ":" + json.dumps(args, sort_keys=True, default=str)
            if key in seen:
                msgs.append({"role": "tool", "tool_call_id": call_id,
                             "content": ("You already ran this exact call; its result "
                                         "was:\n" + seen[key] + "\nDo not repeat it — "
                                         "try different arguments or another tool, or "
                                         "give your final answer.")})
                continue

            # Run-mode gate: ask the user before flagged calls (confirm / semi-auto).
            need, reason = _needs_confirm(mode, name, args)
            if need and on_confirm is not None and not on_confirm(name, args, reason):
                msgs.append({
                    "role": "tool", "tool_call_id": call_id,
                    "content": ("The user declined to run this action. Do not retry "
                                "it as-is; propose an alternative or ask the user how "
                                "to proceed."),
                })
                continue

            on_event("call", name, args)
            result = mcp.call(name, args)
            on_event("result", name, result)
            text = result.get("text") or "(no output)"
            seen[key] = text
            msgs.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": text,
            })

    return "[tool loop] stopped: reached the tool-call limit without a final answer."

