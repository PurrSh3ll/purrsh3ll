#!/usr/bin/env python3
# PurrSh3ll — minimal MCP (Model Context Protocol) client
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# A dependency-free MCP client that speaks JSON-RPC 2.0 over stdio to one or
# more MCP servers (subprocesses), performs the initialize handshake, discovers
# their tools, and dispatches tool calls. It mirrors what a client like Claude
# Code does: every connected server's tools are aggregated into one namespaced
# list (`mcp__<server>__<tool>`) and the client routes a call back to the owning
# server by that name prefix.
#
# No third-party packages are required (the official `mcp` SDK is not installed
# in this environment). The wire protocol is the same, so real MCP servers work
# too — servers are declared in appdata/mcp_servers.json.

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "purragent"
CLIENT_VERSION = "1.0.0"

_NS_SEP = "__"          # mcp__<server>__<tool>
_NS_PREFIX = "mcp"

_KEYRING_SERVICE = "purrsh3ll"   # same store the app uses for model API keys

# Client-side cap on a tool result's text. Our built-in servers already cap their
# output (hacktools 8000, toolkit 20000 chars), but a third-party / connect-only
# server can return an arbitrarily large blob that would blow the model's window.
# We cap those here so no single external result can overflow the context.
MAX_EXTERNAL_OUTPUT = 20000


def _cap_external(result: dict) -> dict:
    """Truncate an external server's result text to MAX_EXTERNAL_OUTPUT chars."""
    text = result.get("text")
    if isinstance(text, str) and len(text) > MAX_EXTERNAL_OUTPUT:
        result["text"] = (text[:MAX_EXTERNAL_OUTPUT]
                          + f"\n… [truncated, {len(text) - MAX_EXTERNAL_OUTPUT} more chars]")
    return result


def is_builtin_server(spec: dict) -> bool:
    """True for a server bundled with purragent (its script lives under
    appdata/mcp_servers/). Built-ins can't be removed by the user."""
    marker = os.path.join("appdata", "mcp_servers")
    return any(marker in str(a) for a in (spec.get("args") or []))


def _namespaced(server: str, tool: str) -> str:
    return f"{_NS_PREFIX}{_NS_SEP}{server}{_NS_SEP}{tool}"


def split_namespaced(name: str):
    """`mcp__demo__ping` -> ('demo', 'ping'); returns (None, name) if not ours."""
    parts = name.split(_NS_SEP)
    if len(parts) >= 3 and parts[0] == _NS_PREFIX:
        return parts[1], _NS_SEP.join(parts[2:])
    return None, name


# --------------------------------------------------------------------------- #
# Token storage — mirrors how the app stores model API keys: OS keyring first
# (service "purrsh3ll", key "mcp:<server>"), falling back to a gitignored JSON
# file. Tokens never touch mcp_servers.json (which is tracked in git).
# --------------------------------------------------------------------------- #
def _token_key(name: str) -> str:
    return f"mcp:{name}"


def _token_json_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "mcp_tokens.json")


def load_token(base_dir: str, name: str) -> str:
    try:
        import keyring
        val = keyring.get_password(_KEYRING_SERVICE, _token_key(name)) or ""
        if val:
            return val
    except Exception:
        pass
    try:
        with open(_token_json_path(base_dir), encoding="utf-8") as f:
            return json.load(f).get(name, "") or ""
    except Exception:
        return ""


def save_token(base_dir: str, name: str, token: str) -> None:
    if not token:
        return
    try:
        import keyring
        keyring.set_password(_KEYRING_SERVICE, _token_key(name), token)
        return
    except Exception:
        pass
    # Fallback JSON store (gitignored). Written 0600 so the token isn't world-readable.
    path = _token_json_path(base_dir)
    data = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    data[name] = token
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def delete_token(base_dir: str, name: str) -> None:
    try:
        import keyring
        keyring.delete_password(_KEYRING_SERVICE, _token_key(name))
    except Exception:
        pass
    path = _token_json_path(base_dir)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if name in data:
            del data[name]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Tool cache — an enabled HTTP server's pulled tool list is stored here so the
# /mcp view can show it without re-fetching every time. Gitignored (derived data).
# --------------------------------------------------------------------------- #
def _tools_cache_path(base_dir: str) -> str:
    return os.path.join(base_dir, "appdata", "mcp_cache.json")


def load_tools_cache(base_dir: str) -> dict:
    try:
        with open(_tools_cache_path(base_dir), encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def get_server_tools(base_dir: str, name: str) -> list:
    return load_tools_cache(base_dir).get(name, []) or []


def save_server_tools(base_dir: str, name: str, tools: list) -> None:
    data = load_tools_cache(base_dir)
    data[name] = tools
    path = _tools_cache_path(base_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def delete_server_tools(base_dir: str, name: str) -> None:
    data = load_tools_cache(base_dir)
    if name in data:
        del data[name]
        path = _tools_cache_path(base_dir)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# HTTP liveness probe — for connect-only (already-running) MCP servers reached
# by URL. "Alive" = the server answers the MCP handshake. Supports SSE (what
# Burp's MCP server uses) and the newer Streamable HTTP transport. This only
# checks reachability; pulling tools over HTTP is a later phase.
# --------------------------------------------------------------------------- #
def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _probe_sse(url: str, token: str, timeout: float):
    """Open the SSE stream and treat receiving the MCP `endpoint` handshake event
    as alive (only an MCP/SSE server emits it). Returns (ok, info)."""
    headers = {"Accept": "text/event-stream", "User-Agent": "Mozilla/5.0"}
    headers.update(_auth_headers(token))
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, f"unauthorized (HTTP {e.code}) — token required or invalid"
        if e.code == 405:
            return None, "not SSE"        # signal caller to try streamable
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, "cannot reach server (is it running?)"
    except Exception as e:
        return False, ("timed out (server slow to respond)"
                       if "timed out" in str(e).lower() else f"error: {e}")

    deadline = time.time() + timeout
    event = None
    try:
        for raw in resp:
            if time.time() > deadline:
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:") and event == "endpoint":
                return True, "SSE"
            elif line == "":
                event = None
    except Exception as e:
        return False, f"stream error: {e}"
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return False, "no MCP handshake (endpoint event) — not an MCP/SSE server?"


def _probe_streamable(url: str, token: str, timeout: float):
    """POST an `initialize` request (Streamable HTTP). Alive = a JSON-RPC result
    comes back. Returns (ok, info)."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "Mozilla/5.0",
    }
    headers.update(_auth_headers(token))
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}}}
    req = urllib.request.Request(url, data=json.dumps(init).encode(),
                                 headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 405:
            return None, "not streamable"     # wrong transport — let caller try SSE
        if e.code in (401, 403):
            return False, f"unauthorized (HTTP {e.code}) — token required or invalid"
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, "cannot reach server (is it running?)"
    except Exception as e:
        return False, ("timed out (server slow to respond)"
                       if "timed out" in str(e).lower() else f"error: {e}")
    # Body is JSON, or SSE-framed (`data: {json}`) — pull the first JSON object.
    for candidate in ([body] if body.lstrip().startswith("{")
                      else [ln[5:].strip() for ln in body.splitlines()
                            if ln.startswith("data:")]):
        try:
            msg = json.loads(candidate)
        except Exception:
            continue
        if "result" in msg:
            info = (msg["result"] or {}).get("serverInfo", {}) or {}
            label = f"{info.get('name', 'mcp')} {info.get('version', '')}".strip()
            return True, label or "connected"
        if "error" in msg:
            return False, f"initialize error: {msg['error'].get('message', msg['error'])}"
    return False, "no initialize response"


def _extract_jsonrpc(body: str, want_id=None):
    """Pull one JSON-RPC message out of an HTTP body that is either raw JSON or
    SSE-framed (`data: {json}` lines). Returns the message with the matching id,
    or None."""
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        candidates = [body]
    else:
        candidates = [ln[5:].strip() for ln in body.splitlines()
                      if ln.startswith("data:")]
    for c in candidates:
        try:
            msg = json.loads(c)
        except Exception:
            continue
        if want_id is None or msg.get("id") == want_id:
            return msg
    return None


def _post_json(url: str, headers: dict, payload: dict, timeout: float):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")


SHORT_DESC_MAXLEN = 100     # chars: catalog one-liner cap


def _short_from_description(desc: str, tool_name: str = "",
                           maxlen: int = SHORT_DESC_MAXLEN) -> str:
    """Derive a one-line catalog short from a tool's description: first sentence
    (up to the first period), whitespace collapsed, truncated to `maxlen`. No
    model — purely extractive. Falls back to the tool name when there's no usable
    description."""
    text = " ".join((desc or "").split())          # collapse newlines/runs
    if not text:
        return tool_name or ""
    dot = text.find(". ")
    if dot == -1 and text.endswith("."):
        dot = len(text) - 1
    first = (text[:dot] if dot != -1 else text).strip().rstrip(".").strip()
    if not first:
        first = text
    if len(first) > maxlen:
        first = first[:maxlen - 1].rstrip() + "…"
    return first


def _index_text_from_tool(t: dict) -> str:
    """Compose RAG-index text for an attached tool from ONLY what the server
    provides — title, description, and input-schema parameter names/descriptions.
    Deterministic and authoritative (no LLM). Used when a server offers no
    purrsh3ll longDescription of its own (built-in tools keep their hand-written
    long + examples)."""
    parts = []
    name = (t.get("name") or "").strip()
    title = (t.get("title") or "").strip()
    if title and title.lower() != name.lower():
        parts.append(title)
    desc = (t.get("description") or "").strip()
    if desc:
        parts.append(desc)
    props = (t.get("inputSchema") or {}).get("properties") or {}
    bits = []
    if isinstance(props, dict):
        for pname, pinfo in props.items():
            pdesc = ((pinfo.get("description") or "").strip()
                     if isinstance(pinfo, dict) else "")
            bits.append(f"{pname}: {pdesc}" if pdesc else str(pname))
    if bits:
        parts.append("Parameters — " + "; ".join(bits))
    return "\n".join(parts).strip()


def fetch_http_tools(url: str, token: str = "", timeout: float = 15.0):
    """Pull an HTTP MCP server's tool list (Streamable HTTP): initialize →
    notifications/initialized → tools/list, carrying the session id if the server
    issues one. Returns (tools, error) — tools is a list of raw MCP tool dicts."""
    if "sse" in url.lower():
        return [], "SSE transport not supported yet (use a Streamable HTTP endpoint)"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "Mozilla/5.0",
    }
    headers.update(_auth_headers(token))
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}}}
    try:
        _status, rh, body = _post_json(url, headers, init, timeout)
        msg = _extract_jsonrpc(body, 1)
        if not msg or "result" not in msg:
            err = (msg or {}).get("error", "no response")
            return [], f"initialize failed: {err}"
        session = rh.get("Mcp-Session-Id") or rh.get("mcp-session-id")
        hdrs = dict(headers)
        hdrs["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if session:
            hdrs["Mcp-Session-Id"] = session
        try:                                          # best-effort ack
            _post_json(url, hdrs, {"jsonrpc": "2.0",
                                   "method": "notifications/initialized"}, timeout)
        except Exception:
            pass
        _status, _rh2, body2 = _post_json(
            url, hdrs, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, timeout)
        msg2 = _extract_jsonrpc(body2, 2)
        if not msg2 or "result" not in msg2:
            err = (msg2 or {}).get("error", "no response")
            return [], f"tools/list failed: {err}"
        tools = msg2["result"].get("tools", []) or []
        # Build a catalog one-liner now (extractive, no model) so it is cached
        # with the tools; server-provided shortDescription is left untouched.
        for t in tools:
            if isinstance(t, dict) and not t.get("shortDescription"):
                t["shortDescription"] = _short_from_description(
                    t.get("description", ""), t.get("name", ""))
        return tools, ""
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return [], f"unauthorized (HTTP {e.code}) — token required or invalid"
        return [], f"HTTP {e.code}"
    except urllib.error.URLError:
        return [], "cannot reach server (is it running?)"
    except Exception as e:
        return [], f"error: {e}"


def call_http_tool(url: str, token: str, tool_name: str, arguments: dict,
                   timeout: float = 30.0) -> dict:
    """Invoke a tool on an HTTP (Streamable) MCP server: initialize →
    notifications/initialized → tools/call, carrying the session id. Returns
    {'text', 'is_error'} — the same shape as the stdio path. Stateless (a fresh
    handshake per call) to keep it simple and robust; no long-lived session."""
    if "sse" in url.lower():
        return {"text": "SSE transport not supported yet (use a Streamable HTTP "
                        "endpoint)", "is_error": True}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "Mozilla/5.0",
    }
    headers.update(_auth_headers(token))
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}}}
    try:
        _status, rh, body = _post_json(url, headers, init, timeout)
        msg = _extract_jsonrpc(body, 1)
        if not msg or "result" not in msg:
            err = (msg or {}).get("error", "no response")
            return {"text": f"initialize failed: {err}", "is_error": True}
        session = rh.get("Mcp-Session-Id") or rh.get("mcp-session-id")
        hdrs = dict(headers)
        hdrs["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if session:
            hdrs["Mcp-Session-Id"] = session
        try:                                          # best-effort ack
            _post_json(url, hdrs, {"jsonrpc": "2.0",
                                   "method": "notifications/initialized"}, timeout)
        except Exception:
            pass
        _status, _rh2, body2 = _post_json(url, hdrs, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments or {}}}, timeout)
        msg2 = _extract_jsonrpc(body2, 2)
        if not msg2 or "result" not in msg2:
            err = (msg2 or {}).get("error", "no response")
            return {"text": f"tool call failed: {err}", "is_error": True}
        result = msg2["result"]
        parts = [b.get("text", "") for b in (result.get("content") or [])
                 if isinstance(b, dict) and b.get("type") == "text"]
        return {"text": "\n".join(parts).strip() or "(no output)",
                "is_error": bool(result.get("isError", False))}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"text": f"unauthorized (HTTP {e.code}) — token required or invalid",
                    "is_error": True}
        return {"text": f"HTTP {e.code}", "is_error": True}
    except urllib.error.URLError:
        return {"text": "cannot reach server (is it running?)", "is_error": True}
    except Exception as e:
        return {"text": f"error: {e}", "is_error": True}


# --------------------------------------------------------------------------- #
# Old HTTP+SSE transport (MCP 2024-11-05) — used by e.g. Burp's MCP server.
# Unlike Streamable HTTP this is stateful: the client opens a long-lived GET
# event stream, learns a POST endpoint from the `endpoint` event, and reads
# JSON-RPC responses back off the stream (correlated by id). We use a transient
# connection per operation (open → handshake → do → close), which keeps it
# simple and bounded while still speaking the protocol correctly.
# --------------------------------------------------------------------------- #
class _SSEConnection:
    """Transient client for the MCP HTTP+SSE transport. Open it, issue requests,
    then close it. Responses arrive on the event stream and are matched by id."""

    def __init__(self, url: str, token: str, timeout: float):
        self.url = url
        self.token = token
        self.timeout = timeout
        self._resp = None
        self._endpoint = None
        self._q: "queue.Queue" = queue.Queue()
        self._reader = None
        self._id = 0

    def open(self):
        headers = {"Accept": "text/event-stream", "User-Agent": "Mozilla/5.0"}
        headers.update(_auth_headers(self.token))
        req = urllib.request.Request(self.url, headers=headers, method="GET")
        self._resp = urllib.request.urlopen(req, timeout=self.timeout)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        deadline = time.monotonic() + self.timeout
        while self._endpoint is None:            # wait for the endpoint handshake
            if time.monotonic() > deadline:
                raise TimeoutError("no endpoint event from SSE server")
            time.sleep(0.02)
        return self

    def _read_loop(self):
        event, data_lines = None, []
        try:
            for raw in self._resp:               # SSE is line-framed, blank-delimited
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    data = "\n".join(data_lines)
                    if event == "endpoint":
                        self._endpoint = urljoin(self.url, data.strip())
                    elif data:                   # default event type is 'message'
                        try:
                            self._q.put(json.loads(data))
                        except Exception:
                            pass
                    event, data_lines = None, []
                elif line.startswith(":"):       # comment / heartbeat
                    continue
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except Exception:
            pass

    def _post(self, payload: dict):
        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
        headers.update(_auth_headers(self.token))
        req = urllib.request.Request(self._endpoint, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=self.timeout).read()

    def request(self, method: str, params: dict = None):
        self._id += 1
        rid = self._id
        self._post({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}})
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no response to {method!r} in {self.timeout}s")
            try:
                msg = self._q.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method} error: {msg['error']}")
                return msg.get("result", {})

    def notify(self, method: str, params: dict = None):
        self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self):
        try:
            self._resp.close()
        except Exception:
            pass


def _sse_handshake(conn: "_SSEConnection"):
    conn.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}})
    try:
        conn.notify("notifications/initialized")
    except Exception:
        pass


def fetch_sse_tools(url: str, token: str = "", timeout: float = 15.0):
    """Pull an SSE MCP server's tool list. Returns (tools, error)."""
    try:
        conn = _SSEConnection(url, token, timeout).open()
    except Exception as e:
        return [], f"cannot open SSE stream: {e}"
    try:
        _sse_handshake(conn)
        tools = (conn.request("tools/list").get("tools", []) or [])
        for t in tools:
            if isinstance(t, dict) and not t.get("shortDescription"):
                t["shortDescription"] = _short_from_description(
                    t.get("description", ""), t.get("name", ""))
        return tools, ""
    except Exception as e:
        return [], f"error: {e}"
    finally:
        conn.close()


def call_sse_tool(url: str, token: str, tool_name: str, arguments: dict,
                  timeout: float = 30.0) -> dict:
    """Invoke a tool on an SSE MCP server. Returns {'text', 'is_error'}."""
    try:
        conn = _SSEConnection(url, token, timeout).open()
    except Exception as e:
        return {"text": f"cannot open SSE stream: {e}", "is_error": True}
    try:
        _sse_handshake(conn)
        result = conn.request("tools/call",
                              {"name": tool_name, "arguments": arguments or {}})
        parts = [b.get("text", "") for b in (result.get("content") or [])
                 if isinstance(b, dict) and b.get("type") == "text"]
        return {"text": "\n".join(parts).strip() or "(no output)",
                "is_error": bool(result.get("isError", False))}
    except Exception as e:
        return {"text": f"tool call failed: {e}", "is_error": True}
    finally:
        conn.close()


def detect_http_transport(url: str, token: str = "", timeout: float = 8.0):
    """Return 'streamable' | 'sse' | None. Uses only safe handshakes (initialize
    / SSE endpoint) — never a tool call — so it has no side effects."""
    def try_streamable() -> bool:
        try:
            headers = {"Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream",
                       "User-Agent": "Mozilla/5.0"}
            headers.update(_auth_headers(token))
            _s, _rh, body = _post_json(url, headers, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                           "clientInfo": {"name": CLIENT_NAME,
                                          "version": CLIENT_VERSION}}}, timeout)
            msg = _extract_jsonrpc(body, 1)
            return bool(msg and "result" in msg)
        except Exception:
            return False

    def try_sse() -> bool:
        try:
            _SSEConnection(url, token, timeout).open().close()
            return True
        except Exception:
            return False

    order = (["sse", "streamable"] if "sse" in url.lower()
             else ["streamable", "sse"])
    for t in order:
        if (t == "streamable" and try_streamable()) or (t == "sse" and try_sse()):
            return t
    return None


def fetch_url_tools(url: str, token: str = "", timeout: float = 15.0):
    """Fetch an HTTP MCP server's tools, auto-selecting Streamable vs old SSE and
    falling back to the other transport. Returns (tools, error)."""
    prefer_sse = "sse" in url.lower()
    primary = fetch_sse_tools if prefer_sse else fetch_http_tools
    fallback = fetch_http_tools if prefer_sse else fetch_sse_tools
    tools, err = primary(url, token, timeout)
    if not err:
        return tools, ""
    tools2, err2 = fallback(url, token, timeout)
    if not err2:
        return tools2, ""
    return [], err                               # report the primary error


def probe_http(url: str, token: str = "", timeout: float = 15.0):
    """Liveness for an HTTP MCP server. Picks SSE vs Streamable by URL hint and
    falls back to the other. Returns (ok: bool, info: str)."""
    sse_first = "sse" in url.lower()
    order = (_probe_sse, _probe_streamable) if sse_first else (_probe_streamable, _probe_sse)
    last = (False, "probe failed")
    for fn in order:
        ok, info = fn(url, token, timeout)
        if ok is None:                    # transport mismatch — try the other one
            last = (False, info)
            continue
        return ok, info                   # alive, or a genuine failure — both final
    return last


# Per-call transport cap. Every tool is bounded by the server's default timeout
# (30s); tools listed here get a longer client-side wait so the transport does
# not clip a legitimately slow call. The value must exceed the tool's own
# internal timeout (see toolkit_server) so the tool returns its clean result
# first. Keyed by bare tool name.
TOOL_CALL_TIMEOUTS = {"http_request": 125.0}

# Default per-call cap for attached HTTP MCP tools (no transport thread caps them
# like stdio does, so the urllib timeout is the bound). Matches the 30s default.
HTTP_CALL_TIMEOUT = 30.0

# How long to WAIT for a tool call. Priority: explicit caller override → the tool's
# own advertised `timeout` (in tools/list) + a small buffer → the legacy per-name
# table → a default for tools that declare nothing (e.g. user-added servers). Never
# wait past the hard cap, whatever a server advertises, so a bad server can't hang the
# agent. When the wait elapses the call is killed (see StdioServer.call_tool).
DEFAULT_CALL_TIMEOUT = 120.0    # tools that advertise no timeout
CALL_TIMEOUT_BUFFER = 10.0      # wait a touch longer than advertised for a clean reply
CALL_TIMEOUT_CAP = 1200.0       # 20 min hard ceiling


# --------------------------------------------------------------------------- #
# One server subprocess
# --------------------------------------------------------------------------- #
class MCPServer:
    """A single MCP server spoken to over its stdio pipes.

    Uses a background reader thread so a hung server can't block the REPL
    forever — requests wait on a queue with a timeout.
    """

    def __init__(self, name: str, command: str, args: list, cwd: str = None,
                 env: dict = None, timeout: float = 30.0):
        self.name = name
        self.command = command
        self.args = list(args or [])
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.proc = None
        self.tools = []            # raw MCP tool dicts from tools/list
        self.server_info = {}
        self.error = None          # set to a string if start() failed
        self._id = 0
        self._q: "queue.Queue" = queue.Queue()
        self._reader = None

    # -- transport ---------------------------------------------------------- #
    def _resolve_command(self) -> str:
        # Run bare python invocations under the same interpreter/venv as us, so a
        # pure-Python server picks up the right environment without extra config.
        if self.command in ("python", "python3"):
            return sys.executable
        return self.command

    def _read_loop(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                # Ignore non-JSON chatter (some servers log to stdout by mistake).
                continue

    def _send(self, msg: dict):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _request(self, method: str, params: dict = None, timeout: float = None):
        """Send a request and wait for the response with the matching id. `timeout`
        overrides the server's default per-request cap (used for slow tools)."""
        wait = self.timeout if timeout is None else timeout
        self._id += 1
        req_id = self._id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method,
                    "params": params or {}})
        # Drain messages until we see our id (skip stray notifications).
        while True:
            try:
                msg = self._q.get(timeout=wait)
            except queue.Empty:
                raise TimeoutError(f"{self.name}: no response to {method!r} "
                                   f"in {wait}s")
            if msg.get("id") == req_id:
                if "error" in msg:
                    err = msg["error"]
                    raise RuntimeError(f"{self.name}: {method} error "
                                       f"{err.get('code')}: {err.get('message')}")
                return msg.get("result", {})
            # else: a notification or a response to something else — ignore.

    def _notify(self, method: str, params: dict = None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> bool:
        """Spawn the server, handshake, and load its tool list. Returns success;
        on failure sets self.error and leaves the server unusable (skipped)."""
        try:
            self.proc = subprocess.Popen(
                [self._resolve_command()] + self.args,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, cwd=self.cwd, env=self.env,
                text=True, bufsize=1,
                start_new_session=True,        # own process group → clean kill on timeout
            )
        except Exception as e:
            self.error = f"spawn failed: {e}"
            return False

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        try:
            init = self._request("initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            })
            self.server_info = init.get("serverInfo", {})
            self._notify("notifications/initialized")
            result = self._request("tools/list")
            self.tools = result.get("tools", []) or []
        except Exception as e:
            self.error = str(e)
            self.close()
            return False
        return True

    def alive(self) -> bool:
        """True while the server subprocess is still running."""
        return self.proc is not None and self.proc.poll() is None

    def call_tool(self, tool_name: str, arguments: dict,
                  timeout: float = None) -> dict:
        """Invoke a tool. Returns {'text', 'is_error'[, 'dead']}. `dead` is set
        when the transport died (broken pipe / process exited), so the manager
        knows it should respawn and retry. `timeout` overrides the default cap."""
        try:
            result = self._request("tools/call", {"name": tool_name,
                                                  "arguments": arguments or {}},
                                   timeout=timeout)
        except TimeoutError:
            # The agent's wait elapsed. Kill the server (and the command it's still
            # running) so the transport is clean for the next call; no auto-retry — a
            # slow tool would just time out again.
            self.close()
            return {"text": f"tool call timed out after "
                            f"{timeout if timeout is not None else self.timeout}s "
                            "(the agent stopped waiting)", "is_error": True}
        except Exception as e:
            return {"text": f"tool call failed: {e}", "is_error": True,
                    "dead": not self.alive() or isinstance(e, (BrokenPipeError, OSError))}
        # MCP result: {"content": [{"type":"text","text":...}], "isError": bool}
        parts = []
        for block in result.get("content", []) or []:
            if block.get("type") == "text":
                parts.append(block.get("text", ""))
        return {"text": "\n".join(parts).strip(),
                "is_error": bool(result.get("isError", False))}

    def close(self):
        if not self.proc:
            return
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        # Kill the whole process group (own session) so a long child command a tool
        # spawned — e.g. an nmap still scanning — dies too, not just the server.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(os.getpgid(self.proc.pid), sig)
            except Exception:
                try:
                    self.proc.terminate() if sig == signal.SIGTERM else self.proc.kill()
                except Exception:
                    pass
            try:
                self.proc.wait(timeout=3)
                break
            except Exception:
                continue
        self.proc = None


# --------------------------------------------------------------------------- #
# Manager: many servers, one aggregated tool list
# --------------------------------------------------------------------------- #
class MCPManager:
    """Loads server declarations, connects to the enabled ones, and exposes a
    single aggregated (namespaced) tool list plus name-based dispatch."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.servers: dict[str, MCPServer] = {}   # only successfully started ones
        self.failures: dict[str, str] = {}        # name -> error
        self.specs: dict[str, dict] = {}          # name -> config (for respawning)
        self._http_transports: dict[str, str] = {}   # url server -> streamable|sse
        self.connected = False

    def _config_path(self) -> str:
        return os.path.join(self.base_dir, "appdata", "mcp_servers.json")

    def load_config(self) -> dict:
        try:
            with open(self._config_path(), encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {"servers": {}}
        except Exception:
            return {"servers": {}}

    def _save_config(self, cfg: dict) -> None:
        path = self._config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, path)             # atomic — never leave a half-written file

    # -- add / remove connect-only (HTTP) servers --------------------------- #
    def add_server(self, name: str, url: str, token: str = "",
                   transport: str = "sse"):
        """Register an already-running MCP server reached by URL, probe whether
        it's alive, and persist it. The token (if any) is stored via the app's
        secret store, never in mcp_servers.json. Returns (ok, info)."""
        ok, info = probe_http(url, token)
        cfg = self.load_config()
        cfg.setdefault("servers", {})[name] = {
            "transport": transport,
            "url": url,
            "has_token": bool(token),     # hint only; the token lives in the keyring
            # New servers are added disabled by default — the user enables them
            # explicitly (separate command). The add-time probe below still reports
            # whether it's reachable right now.
            "enabled": False,
        }
        self._save_config(cfg)
        if token:
            save_token(self.base_dir, name, token)
        else:
            delete_token(self.base_dir, name)
        return ok, info

    def enable_server(self, name: str):
        """Turn a server on. For an HTTP server this pulls its tool list and
        caches it (so /mcp can show it); the tools are NOT wired into the agent
        yet — that's a later step. Returns (status, info): status is
        'enabled' | 'missing' | 'builtin' | 'error'."""
        cfg = self.load_config()
        servers = cfg.get("servers") or {}
        spec = servers.get(name)
        if spec is None:
            return "missing", ""
        if is_builtin_server(spec):
            return "builtin", ""              # always on, nothing to do
        if "url" in spec:
            tools, err = fetch_url_tools(spec["url"], load_token(self.base_dir, name))
            if err:
                return "error", err
            save_server_tools(self.base_dir, name, tools)
            spec["enabled"] = True
            self._save_config(cfg)
            return "enabled", f"{len(tools)} tools"
        # stdio (non-built-in) — just flip the flag; it spawns on next connect.
        spec["enabled"] = True
        self._save_config(cfg)
        return "enabled", ""

    def enable_fetch(self, name: str, timeout: float = 20.0):
        """Network half of enabling an HTTP server: pull its tool list WITHOUT
        touching the config or cache. Returns (status, info, tools) where status
        is 'ready' | 'missing' | 'builtin' | 'stdio' | 'error'. Because it has no
        side effects, an in-flight call is safe to abandon (cancel / timeout) —
        the caller commits separately via enable_commit() only if it wants to."""
        spec = (self.load_config().get("servers") or {}).get(name)
        if spec is None:
            return "missing", "", []
        if is_builtin_server(spec):
            return "builtin", "", []
        if "url" not in spec:
            return "stdio", "", []                # nothing to fetch — just a flag flip
        tools, err = fetch_url_tools(
            spec["url"], load_token(self.base_dir, name), timeout=timeout)
        if err:
            return "error", err, []
        return "ready", f"{len(tools)} tools", tools

    def enable_commit(self, name: str, tools: list) -> str:
        """Commit an enable prepared by enable_fetch: cache the tools and flip the
        flag. Instant (no network). Returns 'enabled' | 'missing'."""
        cfg = self.load_config()
        spec = (cfg.get("servers") or {}).get(name)
        if spec is None:
            return "missing"
        save_server_tools(self.base_dir, name, tools)
        spec["enabled"] = True
        self._save_config(cfg)
        return "enabled"

    def disable_server(self, name: str) -> str:
        """Turn a server off (keeps its cached tools so re-enabling is cheap).
        Returns 'disabled' | 'missing' | 'builtin'."""
        cfg = self.load_config()
        servers = cfg.get("servers") or {}
        spec = servers.get(name)
        if spec is None:
            return "missing"
        if is_builtin_server(spec):
            return "builtin"
        spec["enabled"] = False
        self._save_config(cfg)
        srv = self.servers.pop(name, None)
        if srv is not None:
            srv.close()
        self.specs.pop(name, None)
        self.failures.pop(name, None)
        return "disabled"

    def remove_server(self, name: str) -> str:
        """Delete a user-added server from the config and drop ALL of its data:
        stored token and cached tools. Returns 'removed', 'missing', or 'builtin'
        (a bundled server that can't be removed)."""
        cfg = self.load_config()
        servers = cfg.get("servers") or {}
        spec = servers.get(name)
        if spec is None:
            return "missing"
        if is_builtin_server(spec):
            return "builtin"
        del servers[name]
        cfg["servers"] = servers
        self._save_config(cfg)
        delete_token(self.base_dir, name)
        delete_server_tools(self.base_dir, name)
        # Also drop any live/spec state so it disappears without a full reconnect.
        srv = self.servers.pop(name, None)
        if srv is not None:
            srv.close()
        self.specs.pop(name, None)
        self.failures.pop(name, None)
        return "removed"

    def overview(self, probe: bool = True) -> list:
        """Rich per-server state for the /mcp view — every configured server
        (enabled AND disabled). Each row is a dict:
            {name, spec, enabled, is_http, url, alive, detail, tools, pending}
        `alive` is a live check (HTTP probe / stdio process); `detail` is the
        server version on success or the failure reason; `tools` are the tool
        names for a connected stdio server. Disabled servers are not probed.

        When `probe` is False, HTTP servers are left un-probed (`pending=True`,
        `alive` unknown) so the caller can run the network probes in background
        threads and render a live 'connecting…' state instead of blocking on
        each (potentially slow) endpoint. stdio liveness is always resolved —
        it's a local process poll, not a network round-trip."""
        cfg = self.load_config()
        out = []
        for name, spec in (cfg.get("servers") or {}).items():
            enabled = bool(spec.get("enabled", True))
            is_http = "url" in spec
            row = {"name": name, "spec": spec, "enabled": enabled,
                   "is_http": is_http, "url": spec.get("url", ""),
                   "alive": False, "detail": "", "tools": [],
                   "probed": False, "pending": False}
            if is_http:
                # HTTP servers are checked even when disabled — the user still
                # wants to know if the endpoint is reachable. Enabled ones also
                # show their cached tool list (pulled at enable time; not wired
                # into the agent yet). The liveness probe itself may be slow, so
                # it can be deferred to the caller (`probe=False`).
                if enabled:
                    row["tools"] = [
                        {"name": t.get("name", "?"),
                         "description": t.get("description", "")}
                        for t in get_server_tools(self.base_dir, name)]
                if probe:
                    row["probed"] = True
                    ok, info = self.probe_server(name, spec)
                    row["alive"], row["detail"] = bool(ok), info
                else:
                    row["pending"] = True     # network probe deferred to caller
            elif enabled:
                row["probed"] = True
                srv = self.servers.get(name)
                if srv is not None and srv.alive():
                    nm = srv.server_info.get("name", "")
                    ver = srv.server_info.get("version", "")
                    row["alive"] = True
                    row["detail"] = f"{nm} {ver}".strip() or "connected"
                    row["tools"] = [
                        {"name": t.get("name", "?"),
                         "description": t.get("description", "")}
                        for t in srv.tools]
                else:
                    row["detail"] = self.failures.get(name, "not connected")
            # else: a disabled stdio server isn't spawned, so it stays unprobed.
            out.append(row)
        return out

    def probe_server(self, name: str, spec: dict = None, timeout: float = 15.0):
        """(ok, info) liveness for one server. HTTP servers are probed over the
        network (bounded by `timeout`); stdio servers are considered alive if
        their process is up."""
        if spec is None:
            spec = self.load_config().get("servers", {}).get(name, {})
        if "url" in spec:
            return probe_http(spec["url"], load_token(self.base_dir, name),
                              timeout=timeout)
        srv = self.servers.get(name)
        if srv is not None and srv.alive():
            return True, "alive"
        return False, self.failures.get(name, "not connected")

    def _spawn(self, name: str):
        """Start (or restart) one server from its saved spec. Returns the live
        MCPServer or None, updating self.servers / self.failures."""
        spec = self.specs.get(name)
        if spec is None:
            return None
        if "url" in spec:
            # Connect-only (HTTP) server — there is no subprocess to launch.
            return None
        srv = MCPServer(
            name=name,
            command=spec.get("command", "python3"),
            args=spec.get("args", []),
            cwd=self.base_dir,               # args are relative to the project root
            env=os.environ.copy(),
        )
        if srv.start():
            self.servers[name] = srv
            self.failures.pop(name, None)
            return srv
        self.servers.pop(name, None)
        self.failures[name] = srv.error or "unknown error"
        return None

    def connect(self) -> None:
        """Start every enabled server (idempotent — re-running reconnects)."""
        self.close()
        self.servers.clear()
        self.failures.clear()
        cfg = self.load_config()
        self.specs = {name: spec for name, spec in (cfg.get("servers") or {}).items()
                      if spec.get("enabled", True)}
        for name, spec in self.specs.items():
            if "url" in spec:
                continue        # HTTP (connect-only) servers aren't spawned here
            self._spawn(name)
        self.connected = True

    def has_tools(self) -> bool:
        return bool(self.all_tools())

    def tool_count(self) -> int:
        return len(self.all_tools())

    def openai_tools(self) -> list:
        """Aggregated tools as OpenAI function-calling schemas (namespaced),
        across both spawned stdio servers and enabled HTTP servers."""
        return [e["schema"] for e in self.all_tools()]

    def _openai_schema(self, server: str, t: dict) -> dict:
        """One namespaced OpenAI function schema from a raw MCP tool dict."""
        return {
            "type": "function",
            "function": {
                "name": _namespaced(server, t.get("name", "")),
                "description": t.get("description", ""),
                "parameters": t.get("inputSchema",
                                    {"type": "object", "properties": {}}),
            },
        }

    def all_tools(self) -> list:
        """Every aggregated tool with its three descriptions and ready-made
        OpenAI schema. Feeds the discovery flow: `short` for the always-visible
        catalog, `long` + `examples` for the retriever's index, and `schema` for
        the tools actually surfaced to the model.

        Returns a list of dicts:
            {name (namespaced), short, normal, long, examples, schema}
        """
        out = []
        for name, srv in self.servers.items():           # spawned stdio servers
            for t in srv.tools:
                out.append(self._tool_entry(name, t))
        for name, spec in self.specs.items():             # enabled HTTP servers
            if "url" not in spec:
                continue
            for t in get_server_tools(self.base_dir, name):   # from the tool cache
                if isinstance(t, dict) and t.get("name"):
                    out.append(self._tool_entry(name, t))
        return out

    def _tool_entry(self, server: str, t: dict) -> dict:
        """Aggregated tool dict {name, short, normal, long, examples, schema} for
        one raw MCP tool. Built-in tools ship their own short/long/examples;
        attached servers usually don't, so those are derived from what MCP gives
        us (description + inputSchema) — no LLM."""
        normal = t.get("description", "")
        return {
            "name": _namespaced(server, t.get("name", "")),
            "short": (t.get("shortDescription")
                      or _short_from_description(normal, t.get("name", ""))
                      or normal),
            "normal": normal,
            "long": (t.get("longDescription")
                     or _index_text_from_tool(t)
                     or normal),
            "examples": t.get("exampleQueries") or [],
            "schema": self._openai_schema(server, t),
            "builtin": is_builtin_server(self.specs.get(server, {})),
            "requires": t.get("requires"),        # external binary this tool needs, if any
            "py_missing": t.get("py_missing") or [],   # its unsatisfied python libs, if any
        }

    def schema_for(self, namespaced_name: str):
        """The OpenAI function schema for one namespaced tool, or None."""
        server_name, tool_name = split_namespaced(namespaced_name)
        srv = self.servers.get(server_name)
        tools = (srv.tools if srv is not None
                 else get_server_tools(self.base_dir, server_name))   # HTTP: cache
        for t in tools:
            if isinstance(t, dict) and t.get("name") == tool_name:
                return self._openai_schema(server_name, t)
        return None

    def _resolve_transport(self, name: str, spec: dict, token: str) -> str:
        """Which HTTP transport an attached server speaks. Prefers a persisted
        `transport` in the spec, then a per-session cache, else detects it once
        (safe handshake — never a tool call) and caches. Defaults to streamable."""
        t = spec.get("transport") or self._http_transports.get(name)
        if not t:
            t = detect_http_transport(spec["url"], token) or "streamable"
            self._http_transports[name] = t
        return t

    def _advertised_timeout(self, server_name: str, tool_name: str):
        """The `timeout` a tool advertised in tools/list (seconds), or None."""
        srv = self.servers.get(server_name)
        tools = srv.tools if srv is not None else get_server_tools(self.base_dir,
                                                                   server_name)
        for t in (tools or []):
            if isinstance(t, dict) and t.get("name") == tool_name:
                v = t.get("timeout")
                return v if isinstance(v, (int, float)) and v > 0 else None
        return None

    def _call_timeout(self, server_name: str, tool_name: str, override):
        """How long to wait for this call: explicit override → the tool's advertised
        timeout (+buffer) → the legacy per-name table → the default; always capped."""
        if override is not None:
            return min(float(override), CALL_TIMEOUT_CAP)
        adv = self._advertised_timeout(server_name, tool_name)
        if adv is not None:
            return min(adv + CALL_TIMEOUT_BUFFER, CALL_TIMEOUT_CAP)
        legacy = TOOL_CALL_TIMEOUTS.get(tool_name)
        if legacy is not None:
            return min(legacy, CALL_TIMEOUT_CAP)
        return DEFAULT_CALL_TIMEOUT

    def call(self, namespaced_name: str, arguments: dict, timeout: float = None) -> dict:
        """Route a namespaced tool call to its owning server. Self-healing: if the
        server has died (crash / broken pipe), respawn it and retry once so a dead
        transport doesn't turn every later call into an error. How long to wait is
        decided by _call_timeout (explicit override → the tool's advertised timeout →
        default); when it elapses the running command is killed."""
        server_name, tool_name = split_namespaced(namespaced_name)
        spec = self.specs.get(server_name)
        if spec is None:
            return {"text": f"no such MCP server: {server_name}", "is_error": True}
        call_timeout = self._call_timeout(server_name, tool_name, timeout)

        if "url" in spec:                               # attached HTTP server (external)
            token = load_token(self.base_dir, server_name)
            if self._resolve_transport(server_name, spec, token) == "sse":
                return _cap_external(call_sse_tool(spec["url"], token, tool_name,
                                                   arguments, timeout=call_timeout))
            return _cap_external(call_http_tool(spec["url"], token, tool_name,
                                                arguments, timeout=call_timeout))

        srv = self.servers.get(server_name)
        if srv is None or not srv.alive():          # (re)connect a missing/dead server
            srv = self._spawn(server_name)
        if srv is None:
            return {"text": f"MCP server '{server_name}' is unavailable: "
                            f"{self.failures.get(server_name, 'failed to start')}",
                    "is_error": True}

        result = srv.call_tool(tool_name, arguments, timeout=call_timeout)
        if result.get("dead"):                      # transport died mid-call — retry once
            srv = self._spawn(server_name)
            if srv is not None:
                result = srv.call_tool(tool_name, arguments, timeout=call_timeout)
        result.pop("dead", None)
        # Built-in servers self-cap; cap third-party stdio servers here as a backstop.
        return result if is_builtin_server(spec) else _cap_external(result)

    def status(self) -> list:
        """[(server, ok, info_or_error, [tool_names])] for the /mcp view. HTTP
        (connect-only) servers are probed live; stdio servers report their spawn
        state and tool list."""
        rows = []
        for name, srv in self.servers.items():
            info = srv.server_info.get("name", "") or ""
            ver = srv.server_info.get("version", "")
            label = f"{info} v{ver}".strip() if info else "connected"
            rows.append((name, True, label,
                         [t.get("name", "?") for t in srv.tools]))
        for name, err in self.failures.items():
            rows.append((name, False, err, []))
        # Connect-only HTTP servers: not spawned, so probe each for liveness.
        for name, spec in self.specs.items():
            if "url" not in spec:
                continue
            ok, info = self.probe_server(name, spec)
            rows.append((name, ok, info, []))
        return rows

    def close(self) -> None:
        for srv in self.servers.values():
            srv.close()


# --------------------------------------------------------------------------- #
# Standalone smoke test:  python3 mcp_client.py [--base-dir .]
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    base = "."
    if "--base-dir" in sys.argv:
        base = sys.argv[sys.argv.index("--base-dir") + 1]
    mgr = MCPManager(os.path.abspath(base))
    mgr.connect()
    print(f"connected servers: {list(mgr.servers)}")
    print(f"failures: {mgr.failures}")
    for name, ok, label, tools in mgr.status():
        mark = "OK " if ok else "ERR"
        print(f"  [{mark}] {name}: {label}  tools={tools}")
    print("\nopenai tool schemas:")
    print(json.dumps(mgr.openai_tools(), indent=2))
    # Exercise each tool.
    if mgr.has_tools():
        print("\ncalls:")
        print("  ping:", mgr.call("mcp__demo__ping", {"text": "hi"}))
        print("  add :", mgr.call("mcp__demo__add", {"a": 2, "b": 3}))
        print("  now :", mgr.call("mcp__demo__now", {}))
    mgr.close()
