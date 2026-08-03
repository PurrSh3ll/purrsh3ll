#!/usr/bin/env python3
# PurrSh3ll — toolkit MCP server
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# A dependency-free Model Context Protocol server (JSON-RPC 2.0 over stdio) that
# gives purragent a small, practical toolset for authorized pentesting and
# security research on the local host:
#
#   run_command  — run a shell command, capture stdout/stderr/exit code
#   read_file    — read a text file (optionally a line range)
#   write_file   — create / overwrite / append a file
#   edit_file    — replace a string inside a file (search/replace)
#   list_dir     — list a directory (name, type, size)
#   grep         — regex-search file contents under a path
#   http_request — make an HTTP request and return status/headers/body
#
# Same wire protocol as demo_server.py, so any MCP client talks to it unchanged.
# Paths are resolved relative to the process working directory (the MCP client
# launches this with cwd set to the project root).
#
# SECURITY: run_command / write_file / edit_file are powerful. This server does
# not sandbox or gate them — that is the agent's job (purragent's confirm /
# semi-auto modes). It only enforces timeouts and output-size caps so a single
# call can't hang the agent or flood the model's context.

import fnmatch
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone  # noqa: F401  (available for future tools)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "purr-toolkit"
SERVER_VERSION = "0.1.0"

MAX_OUTPUT = 20000          # chars: cap on any single tool's returned text
DEFAULT_CMD_TIMEOUT = 60    # seconds
DEFAULT_HTTP_TIMEOUT = 30   # seconds
MAX_GREP_HITS = 200


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated, {len(text) - limit} more chars]"


def _resolve(path: str) -> str:
    """Expand $VARS and a leading ~ so paths like ~/Desktop/x or $HOME/x — which
    models commonly emit — land where the user expects (open() would not)."""
    return os.path.expanduser(os.path.expandvars(path))


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
def _tool_run_command(args):
    command = args.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("`command` must be a non-empty string")
    timeout = args.get("timeout", DEFAULT_CMD_TIMEOUT)
    workdir = args.get("workdir") or None
    if workdir:
        workdir = _resolve(workdir)
        if not os.path.isdir(workdir):
            raise ValueError(f"workdir not found: {workdir}")
    try:
        proc = subprocess.run(
            command, shell=True, cwd=workdir, capture_output=True,
            text=True, timeout=float(timeout),
            # Isolate the child's stdin from the server's — otherwise a command
            # that reads stdin (cat, ssh, a prompt…) would consume the JSON-RPC
            # channel and break the MCP transport.
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return f"exit code: (timeout after {timeout}s)\ncommand: {command}"
    out = proc.stdout or ""
    err = proc.stderr or ""
    parts = [f"exit code: {proc.returncode}"]
    if out.strip():
        parts.append("--- stdout ---\n" + out.rstrip("\n"))
    if err.strip():
        parts.append("--- stderr ---\n" + err.rstrip("\n"))
    if not out.strip() and not err.strip():
        parts.append("(no output)")
    return _truncate("\n".join(parts))


def _tool_read_file(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    path = _resolve(path)
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    offset = int(args.get("offset", 0) or 0)      # 0-based starting line
    limit = args.get("limit")                     # number of lines (None = all)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        raise ValueError(f"could not read file: {e}")
    if offset:
        lines = lines[offset:]
    if limit is not None:
        lines = lines[:int(limit)]
    body = "".join(lines)
    header = f"{path} ({os.path.getsize(path)} bytes)\n"
    return _truncate(header + body)


def _tool_write_file(args):
    path = args.get("path")
    content = args.get("content", "")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    if not isinstance(content, str):
        raise ValueError("`content` must be a string")
    path = _resolve(path)
    append = bool(args.get("append", False))
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)
    verb = "appended to" if append else "wrote"
    return f"{verb} {path} ({len(content)} chars)"


def _tool_edit_file(args):
    path = args.get("path")
    old = args.get("old_string")
    new = args.get("new_string", "")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    if not isinstance(old, str) or old == "":
        raise ValueError("`old_string` must be a non-empty string")
    if not isinstance(new, str):
        raise ValueError("`new_string` must be a string")
    path = _resolve(path)
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    replace_all = bool(args.get("replace_all", False))
    with open(path, encoding="utf-8") as f:
        data = f.read()
    count = data.count(old)
    if count == 0:
        raise ValueError("old_string not found in file")
    if count > 1 and not replace_all:
        raise ValueError(f"old_string is not unique ({count} matches); pass "
                         "replace_all=true or give more surrounding context")
    data = data.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return f"edited {path} ({count} replacement{'s' if count != 1 else ''})"


def _tool_list_dir(args):
    path = _resolve(args.get("path", ".") or ".")
    if not os.path.isdir(path):
        raise ValueError(f"not a directory: {path}")
    rows = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        try:
            if os.path.isdir(full):
                rows.append(f"  [dir]  {name}/")
            else:
                rows.append(f"  {os.path.getsize(full):>10}  {name}")
        except OSError:
            rows.append(f"  [?]    {name}")
    header = f"{os.path.abspath(path)}  ({len(rows)} entries)"
    return _truncate("\n".join([header] + rows))


def _tool_grep(args):
    pattern = args.get("pattern")
    if not isinstance(pattern, str) or pattern == "":
        raise ValueError("`pattern` must be a non-empty string")
    path = _resolve(args.get("path", ".") or ".")
    flags = re.IGNORECASE if args.get("ignore_case") else 0
    globpat = args.get("glob")
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"invalid regex: {e}")

    hits = []
    targets = []
    if os.path.isfile(path):
        targets = [path]
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv")]
            for fn in files:
                if globpat and not fnmatch.fnmatch(fn, globpat):
                    continue
                targets.append(os.path.join(root, fn))

    for fpath in targets:
        try:
            with open(fpath, encoding="utf-8", errors="strict") as f:
                for i, line in enumerate(f, 1):
                    if rx.search(line):
                        hits.append(f"{fpath}:{i}: {line.rstrip()}")
                        if len(hits) >= MAX_GREP_HITS:
                            hits.append(f"… [stopped at {MAX_GREP_HITS} matches]")
                            return _truncate("\n".join(hits))
        except (UnicodeDecodeError, OSError):
            continue   # skip binary / unreadable files
    return _truncate("\n".join(hits) if hits else "(no matches)")


def _tool_http_request(args):
    url = args.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("`url` must be a string")
    method = (args.get("method") or "GET").upper()
    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
    body = args.get("body")
    timeout = float(args.get("timeout", DEFAULT_HTTP_TIMEOUT))
    data = body.encode() if isinstance(body, str) else None

    # Default to a browser-like User-Agent — many sites (e.g. Wikimedia) reject
    # urllib's default "Python-urllib/x.y" with 403. Caller can override it.
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = "Mozilla/5.0"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_headers = dict(resp.getheaders())
            payload = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers or {})
        payload = e.read().decode("utf-8", errors="replace") if e.fp else ""
    except Exception as e:
        raise ValueError(f"request failed: {e}")

    hdr_lines = "\n".join(f"  {k}: {v}" for k, v in resp_headers.items())
    return _truncate(f"{method} {url}\nstatus: {status}\n"
                     f"--- headers ---\n{hdr_lines}\n--- body ---\n{payload}")


# name -> (handler, description, inputSchema)
TOOLS = {
    "run_command": (
        _tool_run_command,
        "Run a shell command on the local host and return its exit code, stdout "
        "and stderr. Use for recon/tools (nmap, curl, git…) and anything not "
        "covered by the file tools.",
        {
            "type": "object",
            "properties": {
                "command": {"type": "string",
                            "description": "The shell command to run."},
                "timeout": {"type": "number",
                            "description": f"Seconds before timeout (default {DEFAULT_CMD_TIMEOUT})."},
                "workdir": {"type": "string",
                            "description": "Directory to run in (default: current)."},
            },
            "required": ["command"],
        },
    ),
    "read_file": (
        _tool_read_file,
        "Read a text file. Optionally start at line `offset` and read `limit` "
        "lines (for large files).",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read."},
                "offset": {"type": "integer",
                           "description": "0-based line to start at (default 0)."},
                "limit": {"type": "integer",
                          "description": "Max number of lines to read."},
            },
            "required": ["path"],
        },
    ),
    "write_file": (
        _tool_write_file,
        "Create or overwrite a file with the given content (set append=true to "
        "append). Parent directories are created as needed.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write."},
                "content": {"type": "string", "description": "Content to write."},
                "append": {"type": "boolean",
                           "description": "Append instead of overwrite (default false)."},
            },
            "required": ["path", "content"],
        },
    ),
    "edit_file": (
        _tool_edit_file,
        "Replace an exact string in a file. old_string must be unique unless "
        "replace_all=true. Fails if old_string is missing or ambiguous.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to edit."},
                "old_string": {"type": "string",
                               "description": "Exact text to replace."},
                "new_string": {"type": "string",
                               "description": "Replacement text."},
                "replace_all": {"type": "boolean",
                                "description": "Replace every occurrence (default false)."},
            },
            "required": ["path", "old_string", "new_string"],
        },
    ),
    "list_dir": (
        _tool_list_dir,
        "List a directory's entries with type and size.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Directory to list (default: current)."},
            },
        },
    ),
    "grep": (
        _tool_grep,
        "Search file contents for a regular expression under a path. Returns "
        "matching lines as path:line: text. Skips binary and VCS dirs.",
        {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",
                            "description": "Regular expression to search for."},
                "path": {"type": "string",
                         "description": "File or directory to search (default: current)."},
                "ignore_case": {"type": "boolean",
                                "description": "Case-insensitive match (default false)."},
                "glob": {"type": "string",
                         "description": "Only search files matching this glob (e.g. *.py)."},
            },
            "required": ["pattern"],
        },
    ),
    "http_request": (
        _tool_http_request,
        "Make an HTTP request and return the status, response headers and body. "
        "Use for web/API reconnaissance.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "method": {"type": "string",
                           "description": "HTTP method (default GET)."},
                "headers": {"type": "object",
                            "description": "Request headers as a key/value object."},
                "body": {"type": "string",
                         "description": "Request body (for POST/PUT)."},
                "timeout": {"type": "number",
                            "description": f"Seconds before timeout (default {DEFAULT_HTTP_TIMEOUT})."},
            },
            "required": ["url"],
        },
    ),
}


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing (identical wire protocol to demo_server.py)
# --------------------------------------------------------------------------- #
def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tools_list():
    return [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (_h, desc, schema) in TOOLS.items()
    ]


def _call_tool(name, arguments):
    entry = TOOLS.get(name)
    if entry is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    handler = entry[0]
    try:
        text = handler(arguments or {})
        return {"content": [{"type": "text", "text": str(text)}]}
    except Exception as exc:
        return {"content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True}


def handle_message(msg):
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": _tools_list()})
    if method == "tools/call":
        return _result(req_id, _call_tool(params.get("name"),
                                          params.get("arguments") or {}))
    if req_id is not None:
        return _error(req_id, -32601, f"method not found: {method}")
    return None


def serve():
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            out.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            out.flush()
            continue
        response = handle_message(msg)
        if response is not None:
            out.write(json.dumps(response) + "\n")
            out.flush()


def selftest():
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "purr_toolkit_selftest.txt")
    checks = [
        ("tools/list", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ("run_command", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "run_command",
                                    "arguments": {"command": "echo hello && whoami"}}}),
        ("write_file", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "write_file",
                                   "arguments": {"path": tmp, "content": "alpha\nbeta\n"}}}),
        ("read_file", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "read_file", "arguments": {"path": tmp}}}),
        ("edit_file", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "edit_file",
                                  "arguments": {"path": tmp, "old_string": "beta",
                                                "new_string": "GAMMA"}}}),
        ("grep", {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                  "params": {"name": "grep",
                             "arguments": {"pattern": "GAMMA", "path": tmp}}}),
        ("list_dir", {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "list_dir",
                                 "arguments": {"path": os.path.dirname(tmp)}}}),
    ]
    for label, req in checks:
        resp = handle_message(req)
        result = resp.get("result", {})
        if label == "tools/list":
            names = [t["name"] for t in result.get("tools", [])]
            print(f"[{label}] -> {names}")
        else:
            text = result.get("content", [{}])[0].get("text", "")
            print(f"[{label}] -> {text.splitlines()[0] if text else ''}")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        serve()
