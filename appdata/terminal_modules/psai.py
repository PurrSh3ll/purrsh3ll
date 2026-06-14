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


def _rag_fetch_chunks(query: str, base_dir: str, config: dict, top_n: int = 5) -> list | None:
    """Embed query, search KB, optionally re-rank, return top_n chunks or None on failure."""
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from psrag_query import (_embed, _search, _embedding_model,
                                  _rerank, _RERANK_POOL, _RERANK_MODEL_DEFAULT)
    except ImportError as e:
        _err(f"RAG unavailable: {e}")
        return None

    import gc
    embed_model    = _embedding_model(config)
    cache_dir      = os.path.join(base_dir, "appdata", "rag", "models")
    _rag_cfg       = config.get("rag", {})
    rerank_enabled = bool(_rag_cfg.get("rerank", False))
    rerank_model   = _rag_cfg.get("rerank_model", _RERANK_MODEL_DEFAULT)

    _info("Embedding query…")
    try:
        vec = _embed(query, embed_model, cache_dir)
    except Exception as e:
        _err(f"Embedding failed: {e}")
        return None

    _info("Searching knowledge base…")
    try:
        pool_n = max(_RERANK_POOL, top_n) if rerank_enabled else top_n
        chunks = _search(base_dir, vec, pool_n)
    except Exception as e:
        _err(f"RAG search failed: {e}")
        return None

    if not chunks:
        _info("No relevant chunks found — querying without RAG context.")
        return None

    if rerank_enabled:
        _info(f"Re-ranking results with {rerank_model.split('/')[-1]}…")
        chunks = _rerank(chunks, query, rerank_model, cache_dir)

    gc.collect()
    return chunks[:top_n]


def _rag_build_context(query: str, base_dir: str, config: dict, top_n: int = 5) -> str | None:
    """Run RAG pipeline and return a context-enriched prompt, or None on failure."""
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from psrag_query import _build_prompt
    except ImportError as e:
        _err(f"RAG unavailable: {e}")
        return None

    chunks = _rag_fetch_chunks(query, base_dir, config, top_n)
    if not chunks:
        return None
    return _build_prompt(query, chunks)

_DEFAULT_URLS = {
    "ollama":      "http://localhost:11434/v1",
    "openai":      "https://api.openai.com/v1",
    "anthropic":   "https://api.anthropic.com",
    "groq":        "https://api.groq.com/openai/v1",
    "gemini":      "https://generativelanguage.googleapis.com/v1beta/openai",
    "openrouter":  "https://openrouter.ai/api/v1",
    "huggingface": "https://router.huggingface.co/featherless-ai/v1",
}

_MAX_HISTORY               = 40  # max messages kept in chat session (20 turns); overridden by config
_TERMINAL_HIST_LIMIT       = 8   # max terminal history entries (with output) for psfix/psnext/psreport; overridden by config
_TERMINAL_HIST_BROAD_LIMIT = 120 # max extended history entries (cmd + exit code only) for psfix --analyze; overridden by config


# ── Display flags (set by _load_config, read by external scripts via _ai._SHOW_*) ──
_SHOW_STATS    = True   # psai_show_stats in app_config.json
_SHOW_QUERYING = True   # psai_show_querying in app_config.json

# ── Thinking spinner (used when hide_thinking=True) ───────────────────────────
_SPINNER     = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPINNER_CLR = "\r" + " " * 44 + "\r"   # clear the spinner line


# ── Helpers ───────────────────────────────────────────────────────────────────

def _info(msg: str):
    print(f"\033[90m[psai] {msg}\033[0m", file=sys.stderr)

def _err(msg: str):
    print(f"\033[31m[psai] Error: {msg}\033[0m", file=sys.stderr)

def _print_stats(out_tok: int, elapsed: float, tps: float, in_tok: int = 0):
    """Print dim gray inference stats line to stderr after model response."""
    if not _SHOW_STATS:
        return
    tok_str = f"↓{out_tok} tok" if not in_tok else f"↑{in_tok} ↓{out_tok} tok"
    parts = [tok_str]
    if tps > 0:
        parts.append(f"{tps:.1f} tok/s")
    parts.append(f"{elapsed:.1f}s")
    sys.stderr.write(f"\033[90m{'  ·  '.join(parts)}\033[0m\n")
    sys.stderr.flush()


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config(base_dir: str) -> dict:
    global _SHOW_STATS, _SHOW_QUERYING, _MAX_HISTORY, _TERMINAL_HIST_LIMIT, _TERMINAL_HIST_BROAD_LIMIT
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    # Merge api_profiles.json (profiles stored separately, gitignored)
    profiles_path = os.path.join(base_dir, "appdata", "api_profiles.json")
    try:
        with open(profiles_path, encoding="utf-8") as f:
            cfg["api_providers"] = json.load(f)
    except Exception:
        pass
    _llama = cfg.get("llama", {})
    _SHOW_STATS           = bool(_llama.get("psai_show_stats",          True))
    _SHOW_QUERYING        = bool(_llama.get("psai_show_querying",        True))
    _MAX_HISTORY          = int(_llama.get("chat_max_history",           20)) * 2
    _TERMINAL_HIST_LIMIT       = int(_llama.get("terminal_history_limit",       8))
    _TERMINAL_HIST_BROAD_LIMIT = int(_llama.get("terminal_history_broad_limit", 120))
    return cfg


def _active_profile(config: dict) -> dict:
    prov = config.get("api_providers", {})
    name = prov.get("active", "")
    if not name:
        return {}
    for p in prov.get("profiles", []):
        if p.get("name") == name:
            return p
    return {}


def _resolve_profile(config: dict, profile_arg: str | None) -> dict:
    """Return the profile matching profile_arg by name, or the active profile if None."""
    if not profile_arg:
        return _active_profile(config)
    all_profiles = config.get("api_providers", {}).get("profiles", [])
    for p in all_profiles:
        if p.get("name") == profile_arg:
            return p
    _err(f"Profile \"{profile_arg}\" not found. Check your profiles in AI Settings → API Providers.")
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


_FAST_BRIEF = "Answer as briefly as possible. Use 1-3 sentences. No unnecessary explanations."


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

def _stream_ollama_native(model: str, messages: list, base_url: str,
                          disable_thinking: bool = False,
                          hide_thinking: bool = False) -> str:
    """POST to Ollama native /api/chat — correctly honors think:false."""
    url = base_url.rstrip("/")
    # strip /v1 suffix if present — native API is at root
    if url.endswith("/v1"):
        url = url[:-3]
    url += "/api/chat"

    # Normalize multimodal messages to Ollama native format.
    # Ollama expects content as a plain string and images as a separate list,
    # but psview sends OpenAI-compat format (content as a list with image_url parts).
    normalized = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            text_parts = []
            images = []
            for part in content:
                ptype = part.get("type", "")
                if ptype == "text":
                    text_parts.append(part.get("text", ""))
                elif ptype == "image_url":
                    url_val = part.get("image_url", {}).get("url", "")
                    if ";base64," in url_val:
                        images.append(url_val.split(";base64,", 1)[1])
            entry = {"role": msg.get("role", "user"), "content": "\n".join(text_parts)}
            if images:
                entry["images"] = images
            normalized.append(entry)
        else:
            normalized.append(msg)

    body = {"model": model, "messages": normalized, "stream": True}
    if disable_thinking:
        body["think"] = False

    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    collected = []
    _in_thinking = [False]
    _spin_idx    = [0]
    import time as _time
    _t_start        = _time.time()
    _t_first        = [None]
    _eval_count     = [0]
    _eval_dur_ns    = [0]
    _prompt_count   = [0]
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    msg = d.get("message", {})
                    thinking = msg.get("thinking", "")
                    content  = msg.get("content", "")
                    if thinking and not hide_thinking:
                        if not _in_thinking[0]:
                            sys.stdout.write("\033[90m")
                            sys.stdout.flush()
                            _in_thinking[0] = True
                        sys.stdout.write(thinking)
                        sys.stdout.flush()
                    elif thinking:
                        _in_thinking[0] = True
                        sys.stderr.write(f"\r\033[90m[psai] thinking… {_SPINNER[_spin_idx[0] % len(_SPINNER)]}\033[0m")
                        sys.stderr.flush()
                        _spin_idx[0] += 1
                    if content:
                        if _t_first[0] is None:
                            _t_first[0] = _time.time()
                        if _in_thinking[0]:
                            if not hide_thinking:
                                sys.stdout.write("\033[0m\n")
                                sys.stdout.flush()
                            else:
                                sys.stderr.write(_SPINNER_CLR)
                                sys.stderr.flush()
                            _in_thinking[0] = False
                        sys.stdout.write(content)
                        sys.stdout.flush()
                        collected.append(content)
                    if d.get("done"):
                        _eval_count[0]   = d.get("eval_count", 0)
                        _eval_dur_ns[0]  = d.get("eval_duration", 0)
                        _prompt_count[0] = d.get("prompt_eval_count", 0)
                        break
                except Exception:
                    pass
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m\n")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        print()
        _elapsed = _time.time() - _t_start
        _out_tok = _eval_count[0] or max(1, len("".join(collected)) // 4)
        if _eval_dur_ns[0] > 0:
            _tps = _eval_count[0] / (_eval_dur_ns[0] / 1e9)
        elif _t_first[0]:
            _gen = _elapsed - (_t_first[0] - _t_start)
            _tps = _out_tok / _gen if _gen > 0 else 0
        else:
            _tps = 0
        _print_stats(_out_tok, _elapsed, _tps, in_tok=_prompt_count[0])
    except KeyboardInterrupt:
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)
    return "".join(collected)


def _stream_openai_compat(model: str, messages: list, base_url: str, api_key: str,
                           provider: str = "openai", custom_params: dict = None,
                           hide_thinking: bool = False) -> str:
    """POST to /chat/completions, stream tokens to stdout, return full response text."""
    url = base_url.rstrip("/") + "/chat/completions"

    msgs = list(messages)
    if custom_params:
        custom_params = dict(custom_params)
        system = custom_params.pop("system", None)
        if system and not any(m["role"] == "system" for m in msgs):
            msgs.insert(0, {"role": "system", "content": system})

    body = {"model": model, "messages": msgs, "stream": True,
            "stream_options": {"include_usage": True}}

    if custom_params:
        body.update(custom_params)

    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")

    collected = []
    _in_thinking = [False]
    _spin_idx    = [0]
    import time as _time
    _t_start     = _time.time()
    _t_first     = [None]
    _compl_tok   = [0]
    _prompt_tok  = [0]
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
                    d = json.loads(data_str)
                    # Capture usage wherever it appears — some providers (OpenAI, Groq)
                    # send a separate choices-empty chunk; others (OpenRouter) include
                    # usage in the last choices chunk alongside finish_reason.
                    if d.get("usage"):
                        _compl_tok[0]  = d["usage"].get("completion_tokens", 0) or _compl_tok[0]
                        _prompt_tok[0] = d["usage"].get("prompt_tokens", 0) or _prompt_tok[0]
                    if not d.get("choices"):
                        continue
                    delta    = d["choices"][0]["delta"]
                    thinking = delta.get("reasoning", "")
                    content  = delta.get("content", "")
                    if thinking and not hide_thinking:
                        if not _in_thinking[0]:
                            sys.stdout.write("\033[90m")
                            sys.stdout.flush()
                            _in_thinking[0] = True
                        sys.stdout.write(thinking)
                        sys.stdout.flush()
                    elif thinking:
                        _in_thinking[0] = True
                        sys.stderr.write(f"\r\033[90m[psai] thinking… {_SPINNER[_spin_idx[0] % len(_SPINNER)]}\033[0m")
                        sys.stderr.flush()
                        _spin_idx[0] += 1
                    if content:
                        if _t_first[0] is None:
                            _t_first[0] = _time.time()
                        if _in_thinking[0]:
                            if not hide_thinking:
                                sys.stdout.write("\033[0m\n")
                                sys.stdout.flush()
                            else:
                                sys.stderr.write(_SPINNER_CLR)
                                sys.stderr.flush()
                            _in_thinking[0] = False
                        sys.stdout.write(content)
                        sys.stdout.flush()
                        collected.append(content)
                except Exception:
                    pass
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m\n")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        print()
        _elapsed = _time.time() - _t_start
        _out_tok = _compl_tok[0] or max(1, len("".join(collected)) // 4)
        _gen = (_elapsed - (_t_first[0] - _t_start)) if _t_first[0] else _elapsed
        _tps = _out_tok / _gen if _gen > 0 else 0
        _print_stats(_out_tok, _elapsed, _tps, in_tok=_prompt_tok[0])
    except KeyboardInterrupt:
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)

    return "".join(collected)


def _stream_anthropic(model: str, messages: list, base_url: str, api_key: str,
                       hide_thinking: bool = False) -> str:
    """POST to Anthropic /v1/messages, stream tokens to stdout, return full response text."""
    url = (base_url.rstrip("/") if base_url else "https://api.anthropic.com") + "/v1/messages"

    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_msgs    = [m for m in messages if m["role"] != "system"]

    body = {"model": model, "max_tokens": 4096, "messages": user_msgs, "stream": True}
    if system_parts:
        body["system"] = "\n\n".join(system_parts)

    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "User-Agent":        "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")

    collected = []
    _in_thinking = [False]
    _spin_idx    = [0]
    import time as _time
    _t_start   = _time.time()
    _t_first   = [None]
    _out_tok   = [0]
    _in_tok    = [0]
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                    etype = event.get("type", "")
                    if etype == "content_block_start":
                        block_type = event.get("content_block", {}).get("type", "")
                        _in_thinking[0] = (block_type == "thinking")
                        if _in_thinking[0] and not hide_thinking:
                            sys.stdout.write("\033[90m")
                            sys.stdout.flush()
                    elif etype == "content_block_stop":
                        if _in_thinking[0]:
                            if not hide_thinking:
                                sys.stdout.write("\033[0m\n")
                                sys.stdout.flush()
                            else:
                                sys.stderr.write(_SPINNER_CLR)
                                sys.stderr.flush()
                            _in_thinking[0] = False
                    elif etype == "content_block_delta":
                        delta = event.get("delta", {})
                        dtype = delta.get("type", "")
                        if dtype == "thinking_delta":
                            thinking = delta.get("thinking", "")
                            if thinking and not hide_thinking:
                                sys.stdout.write(thinking)
                                sys.stdout.flush()
                            elif thinking:
                                sys.stderr.write(f"\r\033[90m[psai] thinking… {_SPINNER[_spin_idx[0] % len(_SPINNER)]}\033[0m")
                                sys.stderr.flush()
                                _spin_idx[0] += 1
                        elif dtype == "text_delta":
                            text = delta.get("text", "")
                            if text:
                                if _t_first[0] is None:
                                    _t_first[0] = _time.time()
                                sys.stdout.write(text)
                                sys.stdout.flush()
                                collected.append(text)
                    elif etype == "message_start":
                        _in_tok[0] = event.get("message", {}).get("usage", {}).get("input_tokens", 0)
                    elif etype == "message_delta":
                        _out_tok[0] = event.get("usage", {}).get("output_tokens", 0)
                except Exception:
                    pass
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m\n")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        print()
        _elapsed = _time.time() - _t_start
        _tok     = _out_tok[0] or max(1, len("".join(collected)) // 4)
        _gen     = (_elapsed - (_t_first[0] - _t_start)) if _t_first[0] else _elapsed
        _tps     = _tok / _gen if _gen > 0 else 0
        _print_stats(_tok, _elapsed, _tps, in_tok=_in_tok[0])
    except KeyboardInterrupt:
        if _in_thinking[0] and not hide_thinking:
            sys.stdout.write("\033[0m")
        elif _in_thinking[0]:
            sys.stderr.write(_SPINNER_CLR)
            sys.stderr.flush()
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code} from Anthropic: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)

    return "".join(collected)


def _estimate_prompt_tokens(messages: list) -> int:
    """
    Estimate prompt token count for both text-only and multimodal messages.

    Text tokens:  len(text) // 4  (rough 4-chars-per-token approximation)
    Image tokens: OpenAI tile formula — ceil(w/512)*ceil(h/512)*170 + 85
                  Requires Pillow; falls back to 512-token flat estimate if unavailable.

    Handles both OpenAI-compat content format (list with "image_url") and
    Anthropic format (list with "image" + "source.data").
    """
    import base64 as _b64
    import io as _io
    import math as _math

    try:
        from PIL import Image as _Image
        _pil_ok = True
    except ImportError:
        _pil_ok = False

    def _image_tokens_from_bytes(raw: bytes) -> int:
        if not _pil_ok:
            return 512
        try:
            img = _Image.open(_io.BytesIO(raw))
            w, h = img.size
            # Scale down so longest side ≤ 2048 (mirrors OpenAI high-detail pre-processing)
            max_side = max(w, h)
            if max_side > 2048:
                scale = 2048 / max_side
                w, h = int(w * scale), int(h * scale)
            tiles = _math.ceil(w / 512) * _math.ceil(h / 512)
            return tiles * 170 + 85
        except Exception:
            return 512

    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += len(content) // 4
        elif isinstance(content, list):
            for part in content:
                ptype = part.get("type", "")
                if ptype == "text":
                    total += len(part.get("text", "")) // 4
                elif ptype == "image_url":
                    # OpenAI-compat: "data:<mime>;base64,<data>"
                    url_val = part.get("image_url", {}).get("url", "")
                    if ";base64," in url_val:
                        try:
                            raw = _b64.b64decode(url_val.split(";base64,", 1)[1])
                            total += _image_tokens_from_bytes(raw)
                        except Exception:
                            total += 512
                    else:
                        total += 512
                elif ptype == "image":
                    # Anthropic: source.type == "base64", source.data = b64 string
                    src = part.get("source", {})
                    if src.get("type") == "base64":
                        try:
                            raw = _b64.b64decode(src.get("data", ""))
                            total += _image_tokens_from_bytes(raw)
                        except Exception:
                            total += 512
                    else:
                        total += 512
    return max(1, total)


def _run_llm(provider: str, model: str, messages: list, url: str, api_key: str,
             disable_thinking: bool = False, custom_params: dict = None,
             hide_thinking: bool = False) -> str:
    """Dispatch to correct runner. Returns full assistant response text."""
    try:
        import time as _time
        _tok  = _estimate_prompt_tokens(messages)
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "psai_tok")
        with open(_path, "w") as _f:
            _f.write(f"{int(_time.time() * 1000)}:{_tok}")
    except Exception:
        pass
    if provider == "anthropic":
        return _stream_anthropic(model, messages, url, api_key, hide_thinking)

    # Ollama: use native /api/chat (correctly honors think:false)
    # Fall back to OpenAI-compat only when custom_params are set
    if provider == "ollama" and not custom_params:
        return _stream_ollama_native(model, messages, url, disable_thinking, hide_thinking)

    # Ollama with custom_params: ensure /v1 suffix for OpenAI-compat endpoint
    if provider == "ollama":
        base = url.rstrip("/")
        if not base.endswith("/v1"):
            base += "/v1"
        url = base

    return _stream_openai_compat(model, messages, url, api_key, provider, custom_params, hide_thinking)


# ── Chat session ──────────────────────────────────────────────────────────────

def _session_path(base_dir: str, profile_name: str = "") -> str:
    return os.path.join(base_dir, "appdata", "chat_sessions", "global.json")


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

def mode_ask(args, profile: dict, base_dir: str, api_key: str, config: dict):
    model    = profile.get("model", "")
    provider = profile.get("provider", "ollama")
    url      = args.host or profile.get("url", "") or _DEFAULT_URLS.get(provider, "")

    custom_params    = _parse_custom_params(profile)
    custom_system    = profile.get("custom_system", "").strip()
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking",    False))
    fast_answers     = bool(profile.get("fast_answers", False)) and not custom_params

    query = " ".join(args.query)

    if args.rag:
        enriched = _rag_build_context(query, base_dir, config, args.top_n)
        if enriched:
            query = enriched

    sys_parts = []
    if custom_system:
        sys_parts.append(custom_system)
    if fast_answers:
        sys_parts.append(_FAST_BRIEF)

    msgs = []
    if sys_parts:
        msgs.append({"role": "system", "content": "\n\n".join(sys_parts)})
    msgs.append({"role": "user", "content": query})

    if _SHOW_QUERYING:
        _info(f"Querying {model} via {provider}…\n")
    _run_llm(provider, model, msgs, url, api_key, disable_thinking, custom_params, hide_thinking)


# ── Mode: chat ────────────────────────────────────────────────────────────────

def mode_chat(args, profile: dict, base_dir: str, api_key: str, config: dict):
    model    = profile.get("model", "")
    provider = profile.get("provider", "ollama")
    url      = args.host or profile.get("url", "") or _DEFAULT_URLS.get(provider, "")
    name     = profile.get("name", "default")

    custom_params    = _parse_custom_params(profile)
    custom_system    = profile.get("custom_system", "").strip()
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params
    hide_thinking    = bool(profile.get("hide_thinking",    False))
    fast_answers     = bool(profile.get("fast_answers", False)) and not custom_params

    if args.clear:
        _clear_session(base_dir, name)
        _info("Chat history cleared.")
        return

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
            role_label = "\033[1mYou\033[0m" if msg["role"] == "user" else f"\033[1m{msg.get('model', model)}\033[0m"
            print(f"{role_label}: {msg['content']}\n")
        return

    if not args.query:
        _err('No message provided. Usage: psai chat "your message"  |  psai chat --history  |  psai chat --new')
        sys.exit(1)

    query = " ".join(args.query)

    # query_for_api may be enriched with RAG context, but we always save
    # the original query to history so future turns are not contaminated
    query_for_api = query
    if args.rag:
        enriched = _rag_build_context(query, base_dir, config, args.top_n)
        if enriched:
            query_for_api = enriched

    history.append({"role": "user", "content": query})

    # Build messages for API: keep last _MAX_HISTORY messages, replace last with RAG version if needed
    # Strip non-API fields (e.g. 'model') — some providers reject unknown properties
    msgs_to_send = [{"role": m["role"], "content": m["content"]} for m in history[-_MAX_HISTORY:]]
    if (custom_system or fast_answers) and not any(m["role"] == "system" for m in msgs_to_send):
        sys_parts = []
        if custom_system:
            sys_parts.append(custom_system)
        if fast_answers:
            sys_parts.append(_FAST_BRIEF)
        msgs_to_send = [{"role": "system", "content": "\n\n".join(sys_parts)}] + msgs_to_send
    if query_for_api != query and msgs_to_send:
        msgs_to_send[-1] = {"role": "user", "content": query_for_api}

    if _SHOW_QUERYING:
        _info(f"Chatting with {model} via {provider}…\n")

    response = _run_llm(provider, model, msgs_to_send, url, api_key, disable_thinking, custom_params, hide_thinking)

    if response:
        history.append({"role": "assistant", "content": response, "model": model})
        _save_session(base_dir, name, history)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(prog="psai", add_help=False)
    parser.add_argument("mode",    nargs="?", default="ask", choices=["ask", "chat"])
    parser.add_argument("query",   nargs="*")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE", dest="profile")
    parser.add_argument("-H", "--host",   default="", metavar="URL")
    parser.add_argument("--new",          action="store_true", help="Clear chat history (chat mode)")
    parser.add_argument("-c", "--clear",  action="store_true", help="Clear chat history and exit (chat mode)")
    parser.add_argument("--history",      action="store_true", help="Show chat history (chat mode)")
    parser.add_argument("-r", "--rag",    action="store_true", help="Enrich prompt with RAG context")
    parser.add_argument("-n", "--top-n",  type=int, default=5, metavar="N", dest="top_n",
                        help="Number of RAG chunks (default: 5, used with --rag)")
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
    profile = _resolve_profile(config, args.profile)

    if not profile:
        if not args.profile:
            _err(
                "No active API profile configured.\n"
                "Go to AI Settings > API Providers and set an active profile,\n"
                "or pass a profile name with:  psai ask -p <profile> <query>"
            )
        sys.exit(1)

    api_key = _load_api_key(profile.get("name", ""), base_dir) if profile.get("name") else ""

    if args.mode == "ask":
        mode_ask(args, profile, base_dir, api_key, config)
    elif args.mode == "chat":
        mode_chat(args, profile, base_dir, api_key, config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
