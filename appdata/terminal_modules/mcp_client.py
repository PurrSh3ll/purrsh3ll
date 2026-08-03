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

PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "purragent"
CLIENT_VERSION = "1.0.0"

_NS_SEP = "__"          # mcp__<server>__<tool>
_NS_PREFIX = "mcp"


def _namespaced(server: str, tool: str) -> str:
    return f"{_NS_PREFIX}{_NS_SEP}{server}{_NS_SEP}{tool}"


def split_namespaced(name: str):
    """`mcp__demo__ping` -> ('demo', 'ping'); returns (None, name) if not ours."""
    parts = name.split(_NS_SEP)
    if len(parts) >= 3 and parts[0] == _NS_PREFIX:
        return parts[1], _NS_SEP.join(parts[2:])
    return None, name


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

    def _request(self, method: str, params: dict = None):
        """Send a request and wait for the response with the matching id."""
        self._id += 1
        req_id = self._id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method,
                    "params": params or {}})
        # Drain messages until we see our id (skip stray notifications).
        while True:
            try:
                msg = self._q.get(timeout=self.timeout)
            except queue.Empty:
                raise TimeoutError(f"{self.name}: no response to {method!r} "
                                   f"in {self.timeout}s")
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

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Invoke a tool. Returns {'text', 'is_error'[, 'dead']}. `dead` is set
        when the transport died (broken pipe / process exited), so the manager
        knows it should respawn and retry."""
        try:
            result = self._request("tools/call", {"name": tool_name,
                                                  "arguments": arguments or {}})
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

    def _spawn(self, name: str):
        """Start (or restart) one server from its saved spec. Returns the live
        MCPServer or None, updating self.servers / self.failures."""
        spec = self.specs.get(name)
        if spec is None:
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
        for name in self.specs:
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

        result = srv.call_tool(tool_name, arguments)
        if result.get("dead"):                      # transport died mid-call — retry once
            srv = self._spawn(server_name)
            if srv is not None:
                result = srv.call_tool(tool_name, arguments)
        result.pop("dead", None)
        return result

    def status(self) -> list:
        """[(server, ok, info_or_error, [tool_names])] for the /mcp view."""
        rows = []
        for name, srv in self.servers.items():
            info = srv.server_info.get("name", "") or ""
            ver = srv.server_info.get("version", "")
            label = f"{info} v{ver}".strip() if info else "connected"
            rows.append((name, True, label,
                         [t.get("name", "?") for t in srv.tools]))
        for name, err in self.failures.items():
            rows.append((name, False, err, []))
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
