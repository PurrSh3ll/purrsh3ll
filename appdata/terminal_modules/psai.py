#!/usr/bin/env python3
"""
psai.py — unified AI assistant for PurrSh3ll
Modes: ask, chat  (rag / pentest / report coming later)
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error

_DEFAULT_URLS = {
    "ollama":      "http://localhost:11434/v1",
    "openai":      "https://api.openai.com/v1",
    "anthropic":   "https://api.anthropic.com",
    "groq":        "https://api.groq.com/openai/v1",
    "gemini":      "https://generativelanguage.googleapis.com/v1beta/openai",
    "openrouter":  "https://openrouter.ai/api/v1",
    "huggingface": "https://router.huggingface.co/featherless-ai/v1",
}

_MAX_HISTORY = 40  # max messages kept in chat session (20 turns)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _info(msg: str):
    print(f"\033[90m[psai] {msg}\033[0m", file=sys.stderr)

def _err(msg: str):
    print(f"\033[31m[psai] Error: {msg}\033[0m", file=sys.stderr)


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config(base_dir: str) -> dict:
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _active_profile(config: dict) -> dict:
    prov = config.get("api_providers", {})
    name = prov.get("active", "")
    if not name:
        return {}
    for p in prov.get("profiles", []):
        if p.get("name") == name:
            return p
    return {}


def _load_api_key(profile_name: str, base_dir: str) -> str:
    try:
        import keyring
        val = keyring.get_password("purrsh3ll", profile_name) or ""
        if val:
            return val
    except Exception:
        pass
    try:
        path = os.path.join(base_dir, "appdata", "api_keys.json")
        with open(path, encoding="utf-8") as f:
            return json.load(f).get(profile_name, "")
    except Exception:
        return ""


def _parse_custom_params(profile: dict) -> dict | None:
    raw = profile.get("custom_params", "")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        _err(f"Invalid JSON in custom_params: {raw[:60]}")
        return None


# ── LLM runners ───────────────────────────────────────────────────────────────

def _stream_openai_compat(model: str, messages: list, base_url: str, api_key: str,
                           disable_thinking: bool = False, provider: str = "openai",
                           custom_params: dict = None) -> str:
    """POST to /chat/completions, stream tokens to stdout, return full response text."""
    url = base_url.rstrip("/") + "/chat/completions"

    msgs = list(messages)
    if custom_params:
        custom_params = dict(custom_params)
        system = custom_params.pop("system", None)
        if system and not any(m["role"] == "system" for m in msgs):
            msgs.insert(0, {"role": "system", "content": system})

    body = {"model": model, "messages": msgs, "stream": True}

    if custom_params:
        body.update(custom_params)
    elif disable_thinking:
        m = model.lower()
        if provider == "openai":
            if any(m.startswith(k) or f"/{k}" in m for k in ("o1", "o3", "o4")):
                body["reasoning_effort"] = "low"
        elif provider == "gemini":
            if any(k in m for k in ("2.5", "thinking")):
                body["reasoning_effort"] = "none"
        elif provider == "openrouter":
            if any(k in m for k in ("o1", "o3", "o4", "r1", "thinking", "qwq", "sonnet-3-7")):
                body["reasoning"] = {"effort": "low"}

    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")

    collected = []
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    delta = json.loads(data_str)["choices"][0]["delta"].get("content", "")
                    if delta:
                        sys.stdout.write(delta)
                        sys.stdout.flush()
                        collected.append(delta)
                except Exception:
                    pass
        print()
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)

    return "".join(collected)


def _stream_anthropic(model: str, messages: list, base_url: str, api_key: str,
                       disable_thinking: bool = False) -> str:
    """POST to Anthropic /v1/messages, stream tokens to stdout, return full response text."""
    url = (base_url.rstrip("/") if base_url else "https://api.anthropic.com") + "/v1/messages"

    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_msgs    = [m for m in messages if m["role"] != "system"]

    body = {"model": model, "max_tokens": 4096, "messages": user_msgs, "stream": True}
    if system_parts:
        body["system"] = "\n\n".join(system_parts)
    if disable_thinking:
        if any(k in model.lower() for k in ("claude-3-5", "claude-3-7", "claude-opus-4", "claude-sonnet-4")):
            body["thinking"] = {"type": "disabled"}

    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "User-Agent":        "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")

    collected = []
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                    if event.get("type") == "content_block_delta":
                        delta = event.get("delta", {}).get("text", "")
                        if delta:
                            sys.stdout.write(delta)
                            sys.stdout.flush()
                            collected.append(delta)
                except Exception:
                    pass
        print()
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code} from Anthropic: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)

    return "".join(collected)


def _run_llm(provider: str, model: str, messages: list, url: str, api_key: str,
             disable_thinking: bool = False, custom_params: dict = None) -> str:
    """Dispatch to correct runner. Returns full assistant response text."""
    if provider == "anthropic":
        return _stream_anthropic(model, messages, url, api_key, disable_thinking)

    # Ollama: ensure /v1 suffix for OpenAI-compat endpoint
    if provider == "ollama":
        base = url.rstrip("/")
        if not base.endswith("/v1"):
            base += "/v1"
        url = base

    # Groq: prepend /no_think to last user message for thinking models
    if disable_thinking and provider == "groq" and not custom_params:
        if any(k in model.lower() for k in ("qwq", "deepseek", "-r1", "thinking", "qwen3")):
            messages = list(messages)
            for i in range(len(messages) - 1, -1, -1):
                if messages[i]["role"] == "user":
                    messages[i] = {**messages[i], "content": "/no_think\n" + messages[i]["content"]}
                    break

    return _stream_openai_compat(model, messages, url, api_key, disable_thinking, provider, custom_params)


# ── Chat session ──────────────────────────────────────────────────────────────

def _session_path(base_dir: str, profile_name: str) -> str:
    safe = re.sub(r"[^\w\-]", "_", profile_name)
    return os.path.join(base_dir, "appdata", "chat_sessions", f"{safe}.json")


def _load_session(base_dir: str, profile_name: str) -> list:
    try:
        path = _session_path(base_dir, profile_name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _save_session(base_dir: str, profile_name: str, messages: list):
    path = _session_path(base_dir, profile_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(messages[-_MAX_HISTORY:], f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _clear_session(base_dir: str, profile_name: str):
    path = _session_path(base_dir, profile_name)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


# ── Mode: ask ─────────────────────────────────────────────────────────────────

def mode_ask(args, profile: dict, base_dir: str, api_key: str):
    model    = args.model or profile.get("model", "")
    provider = profile.get("provider", "ollama")
    url      = args.host or profile.get("url", "") or _DEFAULT_URLS.get(provider, "")

    custom_params    = _parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    fast_answers     = bool(profile.get("fast_answers", False)) and not custom_params

    query = " ".join(args.query)
    if fast_answers:
        query += "\n\nAnswer as briefly as possible. Use 1-3 sentences. No unnecessary explanations."

    _info(f"Querying {model} via {provider}…\n")
    _run_llm(provider, model, [{"role": "user", "content": query}],
             url, api_key, disable_thinking, custom_params)


# ── Mode: chat ────────────────────────────────────────────────────────────────

def mode_chat(args, profile: dict, base_dir: str, api_key: str):
    model    = args.model or profile.get("model", "")
    provider = profile.get("provider", "ollama")
    url      = args.host or profile.get("url", "") or _DEFAULT_URLS.get(provider, "")
    name     = profile.get("name", "default")

    custom_params    = _parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

    if args.new:
        _clear_session(base_dir, name)
        _info("Session cleared.")
        if not args.query:
            return

    history = _load_session(base_dir, name)

    if args.history:
        if not history:
            _info("No chat history.")
            return
        for msg in history:
            role_label = "\033[1mYou\033[0m" if msg["role"] == "user" else f"\033[1m{model}\033[0m"
            print(f"{role_label}: {msg['content']}\n")
        return

    if not args.query:
        _err('No message provided. Usage: psai chat "your message"  |  psai chat --history  |  psai chat --new')
        sys.exit(1)

    query = " ".join(args.query)
    history.append({"role": "user", "content": query})

    turns = len(history) // 2
    _info(f"Chatting with {model} via {provider} ({turns} turn{'s' if turns != 1 else ''} in context)…\n")

    response = _run_llm(provider, model, history, url, api_key, disable_thinking, custom_params)

    if response:
        history.append({"role": "assistant", "content": response})
        _save_session(base_dir, name, history)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psai", add_help=False)
    parser.add_argument("mode",    nargs="?", default="ask", choices=["ask", "chat"])
    parser.add_argument("query",   nargs="*")
    parser.add_argument("-m", "--model",  default=None, metavar="MODEL")
    parser.add_argument("--host",         default="", metavar="URL")
    parser.add_argument("--new",          action="store_true", help="Clear chat history (chat mode)")
    parser.add_argument("--history",      action="store_true", help="Show chat history (chat mode)")
    parser.add_argument("--base-dir",     default=None)
    parser.add_argument("-h", "--help",   action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psai — unified AI assistant for PurrSh3ll\n\n"
            "Commands:\n"
            "  psask <query>     Direct question to active profile (no RAG)\n"
            "  pschat <message>  Chat with persistent conversation history\n"
            "  psrag <query>     RAG query against the knowledge base\n\n"
            "Run each command with -h for detailed help."
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    config  = _load_config(base_dir)
    profile = _active_profile(config)

    if not profile and not args.model:
        _err(
            "No active API profile configured.\n"
            "Go to AI Settings > API Providers and set an active profile,\n"
            "or pass a model with:  psai ask -m <model> <query>"
        )
        sys.exit(1)

    api_key = _load_api_key(profile.get("name", ""), base_dir) if profile.get("name") else ""

    if args.mode == "ask":
        mode_ask(args, profile, base_dir, api_key)
    elif args.mode == "chat":
        mode_chat(args, profile, base_dir, api_key)


if __name__ == "__main__":
    main()
