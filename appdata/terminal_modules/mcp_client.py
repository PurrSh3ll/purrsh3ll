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
        return (msg2["result"].get("tools", []) or []), ""
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return [], f"unauthorized (HTTP {e.code}) — token required or invalid"
        return [], f"HTTP {e.code}"
    except urllib.error.URLError:
        return [], "cannot reach server (is it running?)"
    except Exception as e:
        return [], f"error: {e}"


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
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
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
            tools, err = fetch_http_tools(spec["url"], load_token(self.base_dir, name))
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
        tools, err = fetch_http_tools(
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
        return any(s.tools for s in self.servers.values())

    def tool_count(self) -> int:
        return sum(len(s.tools) for s in self.servers.values())

    def openai_tools(self) -> list:
        """Aggregated tools as OpenAI function-calling schemas (namespaced)."""
        out = []
        for name, srv in self.servers.items():
            for t in srv.tools:
                out.append({
                    "type": "function",
                    "function": {
                        "name": _namespaced(name, t.get("name", "")),
                        "description": t.get("description", ""),
                        "parameters": t.get("inputSchema",
                                            {"type": "object", "properties": {}}),
                    },
                })
        return out

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
        for name, srv in self.servers.items():
            for t in srv.tools:
                normal = t.get("description", "")
                out.append({
                    "name": _namespaced(name, t.get("name", "")),
                    "short": t.get("shortDescription") or normal,
                    "normal": normal,
                    "long": t.get("longDescription") or normal,
                    "examples": t.get("exampleQueries") or [],
                    "schema": self._openai_schema(name, t),
                })
        return out

    def schema_for(self, namespaced_name: str):
        """The OpenAI function schema for one namespaced tool, or None."""
        server_name, tool_name = split_namespaced(namespaced_name)
        srv = self.servers.get(server_name)
        if srv is None:
            return None
        for t in srv.tools:
            if t.get("name") == tool_name:
                return self._openai_schema(server_name, t)
        return None

    def call(self, namespaced_name: str, arguments: dict) -> dict:
        """Route a namespaced tool call to its owning server. Self-healing: if the
        server has died (crash / broken pipe), respawn it and retry once so a dead
        transport doesn't turn every later call into an error."""
        server_name, tool_name = split_namespaced(namespaced_name)
        if server_name not in self.specs:
            return {"text": f"no such MCP server: {server_name}", "is_error": True}

        srv = self.servers.get(server_name)
        if srv is None or not srv.alive():          # (re)connect a missing/dead server
            srv = self._spawn(server_name)
        if srv is None:
            return {"text": f"MCP server '{server_name}' is unavailable: "
                            f"{self.failures.get(server_name, 'failed to start')}",
                    "is_error": True}

        call_timeout = TOOL_CALL_TIMEOUTS.get(tool_name)
        result = srv.call_tool(tool_name, arguments, timeout=call_timeout)
        if result.get("dead"):                      # transport died mid-call — retry once
            srv = self._spawn(server_name)
            if srv is not None:
                result = srv.call_tool(tool_name, arguments, timeout=call_timeout)
        result.pop("dead", None)
        return result

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
