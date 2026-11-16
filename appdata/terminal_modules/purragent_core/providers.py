"""purragent_core.providers — extracted from monolithic purragent.py (Phase A refactor)."""

import json
import psai
import sys
import time
import urllib.error

from purragent_core._shared import (AGENT_TEMPERATURE, ANTHROPIC_MAX_TOKENS, ANTHROPIC_VERSION, PURRAGENT_SYSTEM, _THINK_SPINNER, _oai_msgs_to_anthropic, _oai_tools_to_anthropic)
from purragent_core.models import (_env_block)

def query_model(profile: dict, base_dir: str, history: list) -> str:
    provider = profile.get("provider", "ollama")
    model    = profile.get("model", "")
    url      = profile.get("url", "") or psai._DEFAULT_URLS.get(provider, "")
    api_key  = psai._load_api_key(profile.get("name", ""), base_dir)

    custom_params    = psai._parse_custom_params(profile)
    custom_system    = profile.get("custom_system", "").strip()
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking", False))
    temperature      = AGENT_TEMPERATURE   # pinned; not inherited from the profile

    sys_parts = [PURRAGENT_SYSTEM, _env_block()]
    if custom_system:
        sys_parts.append(custom_system)
    msgs = [{"role": "system", "content": "\n\n".join(sys_parts)}] + history

    return psai._run_llm(provider, model, msgs, url, api_key,
                         disable_thinking, custom_params, hide_thinking, temperature)



def _openai_endpoint(profile: dict, base_dir: str):
    """(endpoint, api_key) for the profile's chat endpoint. For OpenAI-compatible
    providers this is …/chat/completions; for the anthropic provider it is the
    …/v1/messages endpoint (the /messages suffix is how _chat_stream routes to the
    Anthropic wire format)."""
    provider = profile.get("provider", "ollama")
    url = profile.get("url", "") or psai._DEFAULT_URLS.get(provider, "")
    if provider == "anthropic":
        base = (url.rstrip("/") or "https://api.anthropic.com")
        endpoint = base + ("/messages" if base.endswith("/v1") else "/v1/messages")
        return endpoint, psai._load_api_key(profile.get("name", ""), base_dir)
    if provider == "ollama":                     # native URL lacks the /v1 suffix
        base = url.rstrip("/")
        url = base if base.endswith("/v1") else base + "/v1"
    endpoint = url.rstrip("/") + "/chat/completions"
    api_key = psai._load_api_key(profile.get("name", ""), base_dir)
    return endpoint, api_key



def _chat_stream_anthropic(endpoint: str, api_key: str, body: dict, on_text,
                           hide_thinking: bool = False, render_reasoning: bool = True,
                           max_seconds: float | None = None, on_activity=None) -> dict:
    """Stream one Anthropic /v1/messages turn, converting the OpenAI-shaped `body`
    (messages + tools) at the wire and returning the SAME normalised assistant dict
    {content, tool_calls} that _chat_stream returns."""
    system, messages = _oai_msgs_to_anthropic(body.get("messages") or [])
    payload = {"model": body.get("model", ""), "messages": messages, "stream": True,
               "max_tokens": int(body.get("max_tokens") or ANTHROPIC_MAX_TOKENS)}
    if system:
        payload["system"] = system
    tools = _oai_tools_to_anthropic(body.get("tools") or [])
    if tools:
        payload["tools"] = tools
        if body.get("tool_choice") in (None, "auto"):
            payload["tool_choice"] = {"type": "auto"}
    for k in ("temperature", "top_p", "top_k", "stop_sequences"):  # whitelist only
        if body.get(k) is not None:
            payload[k] = body[k]
    headers = {"Content-Type": "application/json", "x-api-key": api_key,
               "anthropic-version": ANTHROPIC_VERSION, "User-Agent": "Mozilla/5.0"}
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    psai._debug_dump_request("anthropic (agent)", endpoint, "POST", headers, payload)

    content_parts: list = []
    blocks: dict = {}          # index -> {type, id, name, json}
    thinking = {"on": False, "spin": 0}
    activity_fired = False     # on_activity: fire once on the first content block

    def _end_thinking():
        if not thinking["on"]:
            return
        if not render_reasoning:
            thinking["on"] = False
            return
        if hide_thinking:
            sys.stderr.write("\r" + " " * 44 + "\r")
            sys.stderr.flush()
        else:
            sys.stdout.write("\033[0m\n")
            sys.stdout.flush()
        thinking["on"] = False

    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        on_text(f"[tool loop] HTTP {e.code}: {detail[:400]}")
        return {"role": "assistant", "content": f"[tool loop] HTTP {e.code}"}

    stream_start = time.time()
    with resp:
        for raw in resp:
            if max_seconds and (time.time() - stream_start) > max_seconds:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            etype = ev.get("type", "")
            if on_activity is not None and not activity_fired and etype in (
                    "content_block_start", "content_block_delta"):
                activity_fired = True
                try:
                    on_activity()
                except Exception:                          # noqa: BLE001
                    pass
            if etype == "content_block_start":
                idx = ev.get("index", 0)
                cb = ev.get("content_block") or {}
                if cb.get("type") == "tool_use":
                    blocks[idx] = {"type": "tool_use", "id": cb.get("id"),
                                   "name": cb.get("name", ""), "json": ""}
                else:
                    blocks[idx] = {"type": cb.get("type", "text")}
            elif etype == "content_block_delta":
                d = ev.get("delta") or {}
                dt = d.get("type", "")
                if dt == "text_delta":
                    piece = d.get("text", "")
                    if piece:
                        _end_thinking()
                        content_parts.append(piece)
                        on_text(piece)
                elif dt == "input_json_delta":
                    b = blocks.setdefault(ev.get("index", 0),
                                          {"type": "tool_use", "id": None,
                                           "name": "", "json": ""})
                    b["json"] += d.get("partial_json", "")
                elif dt == "thinking_delta" and render_reasoning:
                    r = d.get("thinking", "")
                    if r and hide_thinking:
                        thinking["spin"] += 1
                        frame = _THINK_SPINNER[thinking["spin"] % len(_THINK_SPINNER)]
                        sys.stderr.write(f"\r\033[90mthinking… {frame}\033[0m")
                        sys.stderr.flush()
                        thinking["on"] = True
                    elif r:
                        if not thinking["on"]:
                            sys.stdout.write("\033[90m")
                        sys.stdout.write(r)
                        sys.stdout.flush()
                        thinking["on"] = True
            elif etype == "error":
                msg = (ev.get("error") or {}).get("message", "unknown error")
                on_text(f"[tool loop] anthropic error: {msg[:300]}")
            elif etype == "message_stop":
                break

    _end_thinking()
    msg = {"role": "assistant", "content": "".join(content_parts) or None}
    tcs = [{"id": b.get("id"), "type": "function",
            "function": {"name": b.get("name", ""), "arguments": b.get("json") or "{}"}}
           for _i, b in sorted(blocks.items()) if b.get("type") == "tool_use"]
    if tcs:
        msg["tool_calls"] = tcs
    return msg



def _chat_stream(endpoint: str, api_key: str, body: dict, on_text,
                 hide_thinking: bool = False, render_reasoning: bool = True,
                 max_seconds: float | None = None, on_activity=None) -> dict:
    """Stream one /chat/completions turn (SSE). Prints content deltas live via
    on_text(piece); accumulates tool_call deltas. Reasoning deltas drive a
    'thinking…' spinner when hide_thinking is set, or print greyed inline when
    not. Returns an assistant message dict {content, tool_calls}.
    `render_reasoning=False` suppresses ALL direct terminal writes for reasoning —
    needed when the caller renders on its own screen (e.g. the btw stream view).
    `max_seconds` caps the whole turn on the wall clock: the per-read socket timeout
    can't stop a model stuck streaming reasoning forever (each token resets it), so
    automated/background calls pass a cap to abort a runaway turn."""
    # Anthropic provider: its endpoint is …/v1/messages (see _openai_endpoint), which
    # needs the Messages wire format — convert + parse there, same return shape.
    if endpoint.rstrip("/").endswith("/messages"):
        return _chat_stream_anthropic(endpoint, api_key, body, on_text,
                                      hide_thinking, render_reasoning, max_seconds,
                                      on_activity)
    body = dict(body)
    body["stream"] = True
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0",
    }
    req = urllib.request.Request(
        endpoint, data=json.dumps(body).encode(), headers=headers, method="POST")
    # Under /debug this prints the exact on-the-wire request (masked key, full
    # body incl. the tool schemas) — same dump psai uses for the text path.
    psai._debug_dump_request("openai-compat (agent)", endpoint, "POST", headers, body)

    content_parts: list = []
    tool_calls: dict = {}      # index -> {id, name, args}
    thinking = {"on": False, "spin": 0}
    activity_fired = False     # on_activity: fire once on the first delta of any kind

    def _end_thinking():
        """Clear the spinner / close the greyed reasoning block once real output
        (content or a tool call) starts."""
        if not thinking["on"]:
            return
        if not render_reasoning:
            thinking["on"] = False
            return
        if hide_thinking:
            sys.stderr.write("\r" + " " * 44 + "\r")
            sys.stderr.flush()
        else:
            sys.stdout.write("\033[0m\n")
            sys.stdout.flush()
        thinking["on"] = False

    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        on_text(f"[tool loop] HTTP {e.code}: {detail[:400]}")
        return {"role": "assistant", "content": f"[tool loop] HTTP {e.code}"}

    stream_start = time.time()
    with resp:
        for raw in resp:                       # SSE: one "data: {json}" per line
            if max_seconds and (time.time() - stream_start) > max_seconds:
                # Runaway turn (e.g. an endless reasoning loop) — abort and keep
                # whatever was streamed so far; closing `resp` drops the connection.
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = chunk.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}

            # First sign of life from the model — let the caller drop any "warming up"
            # spinner BEFORE we render reasoning/content, so the two never collide.
            if on_activity is not None and not activity_fired and (
                    delta.get("reasoning") or delta.get("reasoning_content")
                    or delta.get("content") or delta.get("tool_calls")):
                activity_fired = True
                try:
                    on_activity()
                except Exception:                          # noqa: BLE001
                    pass

            # Reasoning / chain-of-thought: providers name it differently.
            reasoning = delta.get("reasoning") or delta.get("reasoning_content")
            if reasoning and render_reasoning:
                if hide_thinking:
                    thinking["spin"] += 1
                    frame = _THINK_SPINNER[thinking["spin"] % len(_THINK_SPINNER)]
                    sys.stderr.write(f"\r\033[90mthinking… {frame}\033[0m")
                    sys.stderr.flush()
                else:
                    if not thinking["on"]:
                        sys.stdout.write("\033[90m")   # grey the visible thinking
                    sys.stdout.write(reasoning)
                    sys.stdout.flush()
                thinking["on"] = True

            piece = delta.get("content")
            if piece:
                _end_thinking()
                content_parts.append(piece)
                on_text(piece)

            deltas = delta.get("tool_calls") or []
            if deltas:
                _end_thinking()
            for tc in deltas:
                slot = tool_calls.setdefault(tc.get("index", 0),
                                             {"id": None, "name": "", "args": ""})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["args"] += fn["arguments"]

    _end_thinking()   # in case the stream ended still in the thinking phase
    msg = {"role": "assistant", "content": "".join(content_parts) or None}
    if tool_calls:
        msg["tool_calls"] = [
            {"id": s["id"], "type": "function",
             "function": {"name": s["name"], "arguments": s["args"]}}
            for _i, s in sorted(tool_calls.items())
        ]
    return msg

