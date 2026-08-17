#!/usr/bin/env python3
# PurrSh3ll — purragent LLM wire-format conversion (OpenAI ↔ Anthropic)
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Pure, side-effect-free converters extracted from purragent so they can be
# unit-tested in isolation. The agent loop keeps its transcript in OpenAI shape
# (system/user/assistant with `tool_calls`, and `role:"tool"` results); for the
# anthropic provider these translate it to the Messages API at the wire.

import json


def oai_tools_to_anthropic(tools: list) -> list:
    """OpenAI function schemas → Anthropic tool defs (input_schema, no wrapper)."""
    out = []
    for t in tools or []:
        fn = t.get("function") if t.get("type") == "function" else t
        if not fn or not fn.get("name"):
            continue
        out.append({"name": fn["name"],
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters")
                    or {"type": "object", "properties": {}}})
    return out


def oai_msgs_to_anthropic(messages: list):
    """(system_str, anthropic_messages) from an OpenAI-shaped transcript. The system
    message becomes the top-level `system`; assistant tool_calls become `tool_use`
    blocks; `role:"tool"` results become `tool_result` blocks merged into one user
    turn (Anthropic groups a turn's results together)."""
    system_parts, out = [], []
    for m in messages:
        role = m.get("role")
        if role == "system":
            if m.get("content"):
                system_parts.append(m["content"])
        elif role == "tool":
            block = {"type": "tool_result", "tool_use_id": m.get("tool_call_id"),
                     "content": m.get("content") or ""}
            if out and out[-1]["role"] == "user" and out[-1].get("_tr"):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block], "_tr": True})
        elif role == "assistant":
            content = []
            if m.get("content"):
                content.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                try:
                    inp = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    inp = {}
                content.append({"type": "tool_use", "id": tc.get("id"),
                                "name": fn.get("name", ""), "input": inp})
            out.append({"role": "assistant", "content": content or ""})
        else:                                          # user (or anything else)
            out.append({"role": "user", "content": m.get("content") or ""})
    for m in out:
        m.pop("_tr", None)
    return "\n\n".join(system_parts), out
