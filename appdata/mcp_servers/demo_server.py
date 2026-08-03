#!/usr/bin/env python3
# PurrSh3ll — demo MCP server
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# A minimal, dependency-free Model Context Protocol (MCP) server that speaks
# JSON-RPC 2.0 over stdio (newline-delimited messages). It exposes three tiny,
# easy-to-verify tools so you can confirm the agent <-> MCP wiring end to end:
#
#   * ping(text)   -> "pong: <text>"          (one string arg)
#   * add(a, b)    -> a + b                    (two typed numeric args)
#   * now()        -> current server time      (no args; proves data is real)
#
# It intentionally has no third-party dependencies, so it runs on a plain
# Python 3 without installing the official `mcp` SDK. Once the SDK is added to
# the venv this can be rewritten with FastMCP, but the wire protocol is the
# same, so any MCP client (including purragent's future MCP client) can talk
# to it as-is.
#
# Run it directly and it waits for JSON-RPC on stdin:
#     python3 demo_server.py
#
# Quick smoke test without a client:
#     python3 demo_server.py --selftest

import json
import sys
from datetime import datetime, timezone

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "purr-demo"
SERVER_VERSION = "0.1.0"


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
def _tool_ping(args):
    text = args.get("text", "")
    if not isinstance(text, str):
        raise ValueError("`text` must be a string")
    return f"pong: {text}"


def _tool_add(args):
    a = args.get("a")
    b = args.get("b")
    for name, val in (("a", a), ("b", b)):
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise ValueError(f"`{name}` must be a number")
    total = a + b
    return f"{a} + {b} = {total}"


def _tool_now(args):
    # Local time plus UTC, so it is obvious the value comes from the server
    # and not from the model guessing.
    local = datetime.now().astimezone()
    utc = datetime.now(timezone.utc)
    return (
        f"server time: {local.isoformat(timespec='seconds')} "
        f"(UTC {utc.isoformat(timespec='seconds')})"
    )


# name -> (handler, description, inputSchema)
TOOLS = {
    "ping": (
        _tool_ping,
        "Echo a message back. Returns 'pong: <text>'. Use it to confirm the "
        "MCP server is reachable.",
        {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to echo back.",
                }
            },
            "required": ["text"],
        },
    ),
    "add": (
        _tool_add,
        "Add two numbers and return their sum.",
        {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First addend."},
                "b": {"type": "number", "description": "Second addend."},
            },
            "required": ["a", "b"],
        },
    ),
    "now": (
        _tool_now,
        "Return the current date and time from the server (local + UTC). "
        "Takes no arguments.",
        {"type": "object", "properties": {}},
    ),
}


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing
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
    """Return an MCP tools/call result dict for the given tool."""
    entry = TOOLS.get(name)
    if entry is None:
        return {
            "content": [{"type": "text", "text": f"unknown tool: {name}"}],
            "isError": True,
        }
    handler = entry[0]
    try:
        text = handler(arguments or {})
        return {"content": [{"type": "text", "text": str(text)}]}
    except Exception as exc:  # surface tool errors to the model, not the transport
        return {
            "content": [{"type": "text", "text": f"error: {exc}"}],
            "isError": True,
        }


def handle_message(msg):
    """Route one JSON-RPC request/notification; return a response dict or None."""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    # Notifications (no id) never get a response.
    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return _result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    if method == "ping":
        return _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _tools_list()})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        return _result(req_id, _call_tool(name, arguments))

    # Unknown method with an id -> JSON-RPC "method not found".
    if req_id is not None:
        return _error(req_id, -32601, f"method not found: {method}")
    return None


def serve():
    """Read newline-delimited JSON-RPC from stdin, write replies to stdout."""
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


# --------------------------------------------------------------------------- #
# Offline self-test (no MCP client required)
# --------------------------------------------------------------------------- #
def selftest():
    checks = [
        ("initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        ("tools/list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        (
            "ping",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "ping", "arguments": {"text": "hello"}},
            },
        ),
        (
            "add",
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "add", "arguments": {"a": 7, "b": 5}},
            },
        ),
        (
            "now",
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "now", "arguments": {}},
            },
        ),
    ]
    for label, req in checks:
        resp = handle_message(req)
        print(f"[{label}] -> {json.dumps(resp)}")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        serve()
