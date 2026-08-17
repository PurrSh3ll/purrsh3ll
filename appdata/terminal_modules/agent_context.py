#!/usr/bin/env python3
# PurrSh3ll — purragent context-window budgeting + transcript trimming
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Pure, side-effect-free context-window primitives extracted from purragent so they
# can be unit-tested in isolation. A tool loop only APPENDS to its transcript — every
# tool result piles up round after round with no summariser — so on a small window it
# would overflow mid-run. Before each model call the caller trims the transcript to
# the window, preserving the system(+history) preamble and every assistant+tool group
# (splitting a group would orphan a tool result, which the API rejects).

import json

# ── Context budget primitives ──────────────────────────────────────────────────
# We never fill the whole window. Two reasons: quality degrades as a model nears its
# native limit ("lost in the middle" — worse the smaller the model), and the model
# needs room to generate its reply. FILL_FRAC is the quality-safe input ceiling;
# OUTPUT_FLOOR guarantees generation room in *absolute* tokens so a tiny window
# doesn't starve the reply.
FILL_FRAC    = 0.80
OUTPUT_FLOOR = 6000     # tokens always kept free for the model's reply

AGENT_KEEP_LAST_GROUPS = 3         # newest N tool-call groups always kept in full
AGENT_OUTPUT_RESERVE_TOK = 2000    # room left for the model's reply this round
AGENT_DBCTX_FRAC = 0.25            # max share of the window the findings dump may take
AGENT_TRIM_PLACEHOLDER = ("[earlier tool output trimmed to fit the context window — "
                          "the full result is saved as a finding]")


def split_msg_groups(tail: list) -> list:
    """Split post-preamble messages into groups: each an assistant(tool_calls) turn
    plus the tool results answering it, so trimming never orphans a tool result."""
    groups: list = []
    for m in tail:
        if m.get("role") == "assistant" or not groups:
            groups.append([m])
        else:
            groups[-1].append(m)
    return groups


def msgs_chars(msgs: list) -> int:
    return sum(len(m.get("content") or "")
               + (len(json.dumps(m.get("tool_calls"), default=str))
                  if m.get("tool_calls") else 0)
               for m in msgs)


def msgs_budget_chars(maxc, schemas: list):
    """Char budget for a tool-loop's msgs before a call: the model window minus an output
    reserve and the always-sent tools-field, in chars (~4/token, like _conv_budget).
    None when the window `maxc` is unknown → caller skips trimming (today's behaviour)."""
    if not maxc:
        return None
    try:
        schema_chars = len(json.dumps(schemas, default=str))
    except Exception:                                  # noqa: BLE001
        schema_chars = 0
    return max(0, int(maxc * 4 * FILL_FRAC) - AGENT_OUTPUT_RESERVE_TOK * 4 - schema_chars)


def trim_agent_msgs(msgs: list, budget_chars, preamble: int = 2) -> bool:
    """Keep a tool-loop's msgs within budget_chars, preserving the first `preamble`
    messages (system[+history]) and every assistant+tool group after them. Tier 1: blank
    out big OLD tool outputs (keeping the call trail so the model won't repeat work).
    Tier 2: drop whole oldest groups. Last resort: hard-cap the oldest kept tool result.
    Mutates msgs; returns True if it trimmed anything."""
    if budget_chars is None or msgs_chars(msgs) <= budget_chars:
        return False
    head, groups = msgs[:preamble], split_msg_groups(msgs[preamble:])
    trimmed = False

    # Tier 1 — replace large tool-result bodies in older groups with a placeholder.
    old = groups[:-AGENT_KEEP_LAST_GROUPS] if len(groups) > AGENT_KEEP_LAST_GROUPS else []
    for g in old:
        for m in g:
            if (m.get("role") == "tool"
                    and len(m.get("content") or "") > len(AGENT_TRIM_PLACEHOLDER)):
                m["content"] = AGENT_TRIM_PLACEHOLDER
                trimmed = True
    msgs[:] = head + [m for g in groups for m in g]
    if msgs_chars(msgs) <= budget_chars:
        return trimmed

    # Tier 2 — drop whole oldest groups, always keeping the last K.
    while len(groups) > AGENT_KEEP_LAST_GROUPS:
        groups.pop(0)
        trimmed = True
        msgs[:] = head + [m for g in groups for m in g]
        if msgs_chars(msgs) <= budget_chars:
            return trimmed

    # Last resort — one huge kept group + big system still over: hard-cap a tool body
    # so we never ship an over-window request.
    over = msgs_chars(msgs) - budget_chars
    if over > 0:
        for m in msgs[preamble:]:
            if m.get("role") == "tool" and len(m.get("content") or "") > over + 200:
                m["content"] = m["content"][:len(m["content"]) - over - 200] + "\n[…truncated]"
                trimmed = True
                break
    return trimmed
