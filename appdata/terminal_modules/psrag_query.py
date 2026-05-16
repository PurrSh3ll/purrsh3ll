#!/usr/bin/env python3
"""
psrag_query.py — RAG query engine for PurrSh3ll
Called by the psrag zsh function.
"""

import argparse
import gc
import json
import os
import pty
import re
import select
import subprocess
import sys
import urllib.request
import urllib.error

# Strip ANSI escape codes that ollama outputs (spinner, colors, cursor movement)
_ANSI_RE = re.compile(rb'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


# ── Config helpers ────────────────────────────────────────────────────────────

def _load_config(base_dir: str) -> dict:
    try:
        with open(os.path.join(base_dir, "appdata", "app_config.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _kb_path(config: dict, base_dir: str) -> str:
    rag = config.get("rag", {})
    if rag.get("knowledge_base", "braindump") == "braindump":
        return os.path.join(base_dir, "appmodules", "BrainDump")
    return rag.get("custom_path", "")


def _embedding_model(config: dict) -> str:
    return config.get("rag", {}).get(
        "embedding_model",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    )


def _active_profile(config: dict) -> dict:
    """Return the active API provider profile, or {} if none configured."""
    prov_cfg = config.get("api_providers", {})
    active_name = prov_cfg.get("active", "")
    if not active_name:
        return {}
    for profile in prov_cfg.get("profiles", []):
        if profile.get("name") == active_name:
            return profile
    return {}


# ── RAG pipeline ──────────────────────────────────────────────────────────────

def _embed(query: str, model_name: str, cache_dir: str) -> list:
    try:
        from fastembed import TextEmbedding
    except ImportError:
        _err("fastembed is not installed. Run: pip install fastembed")
        sys.exit(1)

    kwargs = {"model_name": model_name}
    if cache_dir:
        kwargs["cache_dir"] = cache_dir
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = TextEmbedding(**kwargs)
    try:
        vec = [v.tolist() for v in model.embed([query])][0]
    finally:
        del model
        gc.collect()
    return vec


def _search(base_dir: str, query_vec: list, top_n: int) -> list:
    try:
        import chromadb
        from chromadb.api.client import SharedSystemClient
        SharedSystemClient.clear_system_cache()
    except ImportError:
        _err("chromadb is not installed. Run: pip install chromadb")
        sys.exit(1)

    db_path = os.path.join(base_dir, "appdata", "rag", "chroma_db")
    if not os.path.exists(db_path):
        _err("Vector database not found.\nRun 'Refresh index' in Settings > RAG first.")
        sys.exit(1)

    client = chromadb.PersistentClient(path=db_path)
    try:
        col = client.get_collection("rag_kb")
    except Exception:
        _err("Collection 'rag_kb' not found. Run Refresh index first.")
        sys.exit(1)

    count = col.count()
    if count == 0:
        _err("Knowledge base is empty. Add files and run Refresh index.")
        sys.exit(1)

    results = col.query(
        query_embeddings=[query_vec],
        n_results=min(top_n, count),
        include=["documents", "metadatas", "distances"],
    )
    chunks = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        chunks.append({"text": doc, "meta": meta, "distance": dist})
    return chunks


def _build_prompt(query: str, chunks: list) -> str:
    parts = []
    for i, c in enumerate(chunks, 1):
        src     = c["meta"].get("source", "")
        heading = c["meta"].get("heading", "")
        label   = f"[{i}] {src}" + (f"  ({heading})" if heading else "")
        parts.append(f"{label}\n{c['text']}")

    context = "\n\n---\n\n".join(parts)
    return (
        "Use the following knowledge base context to answer the question.\n"
        "Answer only based on the provided context. "
        "If the context does not contain enough information, say so clearly.\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {query}\n\n"
        "Answer:"
    )


# ── Ollama runner ─────────────────────────────────────────────────────────────

def _run_ollama(model: str, prompt: str, disable_thinking: bool = False,
                host: str = ""):
    """
    Run `ollama run <model>` with the prompt via stdin.
    Uses a PTY for stdout so ollama streams tokens instead of buffering.
    stdin is a regular PIPE (non-TTY) so ollama treats it as non-interactive
    and exits automatically after responding — no /bye needed, no >>> prompts.
    Falls back to non-streaming subprocess if PTY is unavailable.
    host is passed as OLLAMA_HOST env variable (e.g. http://192.168.1.10:11434).
    """
    cmd = ["ollama", "run", "--nowordwrap"]
    if disable_thinking:
        cmd.append("--think=false")
    cmd.append(model)
    input_bytes = prompt.encode("utf-8") + b"\n"

    env = os.environ.copy()
    if host:
        env["OLLAMA_HOST"] = host

    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,   # non-TTY stdin → non-interactive mode
            stdout=slave_fd,         # PTY slave → ollama streams output
            stderr=subprocess.DEVNULL,
            env=env,
        )
        os.close(slave_fd)

        proc.stdin.write(input_bytes)
        proc.stdin.flush()
        proc.stdin.close()

        while True:
            try:
                r, _, _ = select.select([master_fd], [], [], 0.2)
                if r:
                    data = os.read(master_fd, 4096)
                    clean = _ANSI_RE.sub(b"", data)
                    if clean:
                        sys.stdout.buffer.write(clean)
                        sys.stdout.flush()
                if proc.poll() is not None:
                    # drain any remaining buffered output
                    try:
                        while select.select([master_fd], [], [], 0.05)[0]:
                            data = os.read(master_fd, 4096)
                            clean = _ANSI_RE.sub(b"", data)
                            if clean:
                                sys.stdout.buffer.write(clean)
                                sys.stdout.flush()
                    except OSError:
                        pass
                    break
            except OSError:
                break

        try:
            os.close(master_fd)
        except OSError:
            pass
        proc.wait()
        print()

    except Exception as e:
        _info(f"PTY unavailable ({e}), falling back to non-streaming mode…")
        result = subprocess.run(cmd, input=input_bytes, capture_output=True, env=env)
        if result.stdout:
            clean = _ANSI_RE.sub(b"", result.stdout)
            sys.stdout.buffer.write(clean)
            sys.stdout.flush()
        print()


# ── OpenAI-compatible runner ───────────────────────────────────────────────────

def _run_openai_compat(model: str, prompt: str, base_url: str, api_key: str,
                       disable_thinking: bool = False, provider: str = "openai"):
    """
    Call an OpenAI-compatible /v1/chat/completions endpoint (openai, groq, etc.)
    and stream the response to stdout.
    """
    # HuggingFace requires the model in the URL path:
    # https://api-inference.huggingface.co/models/{model}/v1/chat/completions
    if provider == "huggingface":
        url = base_url.rstrip("/") + f"/models/{model}/v1/chat/completions"
    else:
        url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model":    model,
        "messages": [{"role": "user", "content": prompt}],
        "stream":   True,
    }
    if disable_thinking:
        m = model.lower()
        if provider == "openai":
            # Only o-series reasoning models support reasoning_effort
            _OPENAI_REASONING = ("o1", "o3", "o4")
            if any(m.startswith(k) or f"/{k}" in m for k in _OPENAI_REASONING):
                body["reasoning_effort"] = "low"
        elif provider == "gemini":
            # Gemini 2.5+ and thinking-exp models support reasoning_effort
            _GEMINI_THINKING = ("2.5", "thinking")
            if any(k in m for k in _GEMINI_THINKING):
                body["reasoning_effort"] = "none"
        elif provider == "openrouter":
            # OpenRouter forwards reasoning_effort to underlying reasoning models
            _OR_REASONING = ("o1", "o3", "o4", "r1", "thinking", "qwq", "sonnet-3-7")
            if any(k in m for k in _OR_REASONING):
                body["reasoning"] = {"effort": "low"}
        # Note: Groq uses /no_think token in the message (handled in prompt)
        # Note: HuggingFace models don't expose thinking parameters
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
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
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0]["delta"].get("content", "")
                    if delta:
                        sys.stdout.write(delta)
                        sys.stdout.flush()
                except Exception:
                    pass
        print()
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code} from {url}: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)


# ── Anthropic runner ───────────────────────────────────────────────────────────

def _run_anthropic(model: str, prompt: str, base_url: str, api_key: str,
                   disable_thinking: bool = False):
    """
    Call the Anthropic messages API and stream the response to stdout.
    base_url defaults to https://api.anthropic.com if empty.
    """
    url = (base_url.rstrip("/") if base_url else "https://api.anthropic.com") + "/v1/messages"
    body = {
        "model":      model,
        "max_tokens": 4096,
        "messages":   [{"role": "user", "content": prompt}],
        "stream":     True,
    }
    if disable_thinking:
        # Extended thinking supported on claude-3-5-sonnet and newer only
        _ANTHROPIC_THINKING = ("claude-3-5", "claude-3-7", "claude-opus-4", "claude-sonnet-4")
        if any(k in model.lower() for k in _ANTHROPIC_THINKING):
            body["thinking"] = {"type": "disabled"}
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "User-Agent":        "Mozilla/5.0",
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                try:
                    event = json.loads(data_str)
                    if event.get("type") == "content_block_delta":
                        delta = event.get("delta", {}).get("text", "")
                        if delta:
                            sys.stdout.write(delta)
                            sys.stdout.flush()
                except Exception:
                    pass
        print()
    except urllib.error.HTTPError as e:
        _err(f"HTTP {e.code} from Anthropic: {e.read().decode('utf-8', errors='replace')}")
        sys.exit(1)
    except Exception as e:
        _err(f"Request failed: {e}")
        sys.exit(1)


def _run_llm(provider: str, model: str, prompt: str,
             url: str, api_key: str,
             disable_thinking: bool = False):
    """Dispatch to the correct runner based on provider."""
    if provider == "ollama":
        _run_ollama(model, prompt, disable_thinking, url)
    elif provider == "anthropic":
        _run_anthropic(model, prompt, url, api_key, disable_thinking)
    else:
        # For Groq thinking models, /no_think token disables chain-of-thought
        if disable_thinking and provider == "groq":
            _GROQ_THINKING = ("qwq", "deepseek", "-r1", "thinking", "qwen3")
            if any(k in model.lower() for k in _GROQ_THINKING):
                prompt = "/no_think\n" + prompt
        _run_openai_compat(model, prompt, url, api_key, disable_thinking, provider)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _info(msg: str):
    print(f"\033[90m[psrag] {msg}\033[0m", file=sys.stderr)

def _err(msg: str):
    print(f"\033[31m[psrag] Error: {msg}\033[0m", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="psask", add_help=False)
    parser.add_argument("query",           nargs="+")
    parser.add_argument("-n",              type=int, default=5, metavar="N", dest="top_n")
    parser.add_argument("-m", "--model",   default=None, metavar="MODEL")
    parser.add_argument("--host",          default="", metavar="URL",
                        help="Ollama host (sets OLLAMA_HOST, e.g. http://192.168.1.10:11434)")
    parser.add_argument("--no-context",    action="store_true")
    parser.add_argument("--show-sources",  action="store_true")
    parser.add_argument("--base-dir",      default=None)
    parser.add_argument("-h", "--help",    action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "psask — query the PurrSh3ll RAG knowledge base\n\n"
            "Usage: psask [options] <query>\n\n"
            "Options:\n"
            "  -n N             Context chunks to retrieve (default: 5)\n"
            "  -m MODEL         Model override (default: from active API profile)\n"
            "  --host URL       Provider host/base URL override\n"
            "  --no-context     Query the model directly without RAG context\n"
            "  --show-sources   Print source files and scores before answer\n"
            "  -h, --help       Show this help\n\n"
            "Examples:\n"
            '  psask "what is XSS?"\n'
            '  psask -n 3 --show-sources "how to enumerate subdomains"\n'
            '  psask -m llama3.2 "explain SQL injection"\n'
            '  psask --host http://192.168.1.10:11434 "query"\n'
            '  psask --no-context "what is 2+2"'
        )
        sys.exit(0)

    query    = " ".join(args.query)
    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    config            = _load_config(base_dir)
    llama_cfg         = config.get("llama", {})
    profile           = _active_profile(config)

    if not profile and not args.model:
        _err(
            "No active API profile configured.\n"
            "Go to AI Settings > API Providers and set an active profile,\n"
            "or pass a model directly with:  psask -m <model> <query>"
        )
        sys.exit(1)

    provider          = profile.get("provider", "ollama")
    model             = args.model or profile.get("model", "")
    if not model:
        _err(
            f"Active profile \"{profile.get('name', '?')}\" has no model configured.\n"
            "Edit the profile in AI Settings > API Providers."
        )
        sys.exit(1)

    _DEFAULT_URLS = {
        "ollama":      "http://localhost:11434",
        "openai":      "https://api.openai.com/v1",
        "anthropic":   "https://api.anthropic.com",
        "groq":        "https://api.groq.com/openai/v1",
        "gemini":      "https://generativelanguage.googleapis.com/v1beta/openai",
        "openrouter":  "https://openrouter.ai/api/v1",
        "huggingface": "https://router.huggingface.co/hf-inference",
    }
    profile_url       = profile.get("url", "") or _DEFAULT_URLS.get(provider, "")
    host              = args.host or (profile_url if provider == "ollama" else "")
    api_url           = args.host or profile_url
    embed_model       = _embedding_model(config)
    cache_dir         = os.path.join(base_dir, "appdata", "rag", "models")
    disable_thinking  = bool(llama_cfg.get("ai_disable_thinking",
                            llama_cfg.get("ollama_disable_thinking", False)))
    fast_answers      = bool(llama_cfg.get("ai_fast_answers",
                            llama_cfg.get("ollama_fast_answers", False)))

    # Load API key for non-ollama providers
    api_key = ""
    if provider != "ollama" and profile.get("name"):
        try:
            keys_path = os.path.join(base_dir, "appdata", "api_keys.json")
            with open(keys_path, encoding="utf-8") as _f:
                api_key = json.load(_f).get(profile["name"], "")
        except Exception:
            pass

    _FAST_SUFFIX = (
        "\n\nAnswer as briefly as possible. "
        "Use 1-3 sentences. No unnecessary explanations."
    )

    if args.no_context:
        _info(f"Querying {model} via {provider} (no context)…")
        q = query + _FAST_SUFFIX if fast_answers else query
        _run_llm(provider, model, q, api_url if provider != "ollama" else host,
                 api_key, disable_thinking)
        return

    _info("Embedding query…")
    vec = _embed(query, embed_model, cache_dir)

    _info("Searching knowledge base…")
    chunks = _search(base_dir, vec, args.top_n)

    if not chunks:
        _err("No relevant chunks found.")
        sys.exit(1)

    if args.show_sources:
        _info("Sources:")
        seen = set()
        for c in chunks:
            src = c["meta"].get("source", "?")
            if src not in seen:
                seen.add(src)
                score = 1.0 - c["distance"]
                print(f"  \033[90m• {src}  (score={score:.3f})\033[0m", file=sys.stderr)
        print(file=sys.stderr)

    prompt = _build_prompt(query, chunks)
    if fast_answers:
        prompt += _FAST_SUFFIX
    _info(f"Querying {model} via {provider}…\n")
    _run_llm(provider, model, prompt, api_url, api_key, disable_thinking)


if __name__ == "__main__":
    main()
