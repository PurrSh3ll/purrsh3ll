"""purragent_core.agent — extracted from monolithic purragent.py (Phase A refactor)."""

from rich.text import Text
import conv_memory
import json
import os
import psai

from purragent_core._shared import (AGENT_TEMPERATURE, AGENT_TURN_MAX_SECONDS, MEMORY_LOOKUP_TOKENS, _SUMMARY_SYSTEM, console)
from purragent_core.models import _conv_budget
from purragent_core.providers import (_chat_stream, _openai_endpoint)

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
