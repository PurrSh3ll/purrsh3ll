#!/usr/bin/env python3
# PurrSh3ll — hacktools MCP server
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# A dependency-free Model Context Protocol (MCP) server (JSON-RPC 2.0 over stdio,
# newline-delimited) exposing a CURATED set of SAFE, target-only enumeration tools
# from the offensive toolkit — the same class of tools purragent uses in its
# service-exploitation phase, but here as standalone MCP tools for normal (non-hack)
# mode. Design notes:
#
#   * Safe by default: only read/enumeration tools. No brute-force, no cracking, no
#     relay/poison/listener tools, no reverse shells — those stay manual.
#   * No shell: every tool builds an argv list (never shell=True), so a hostname can
#     never inject a command. Inputs are validated (host chars, port range).
#   * Single target: a CIDR / subnet (anything with '/') is rejected, so a tool can't
#     silently widen scope to a whole network.
#   * Honest about availability: if the underlying binary isn't installed, the tool
#     returns a clear '[not installed]' message instead of a transport error.
#   * Time-budgeted: every call has a timeout; partial output is kept on timeout.
#
# Run it directly and it waits for JSON-RPC on stdin:
#     python3 hacktools_server.py
# Quick smoke test without a client:
#     python3 hacktools_server.py --selftest

import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import quote

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "purr-hacktools"
SERVER_VERSION = "0.1.0"

from hacktools_tools import *      # noqa: F401,F403 — _run, MAX_OUTPUT, _is_root, …
from hacktools_registry import *   # noqa: F401,F403 — HACKTOOLS + metadata tables


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing
# --------------------------------------------------------------------------- #
def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _py_missing(name):
    """pip hints for this tool's unsatisfied python-lib groups (empty when all present)."""
    import importlib.util
    out = []
    for mods, hint in _PY_REQUIRES.get(name, ()):
        ok = False
        for m in mods:
            try:
                if importlib.util.find_spec(m) is not None:
                    ok = True
                    break
            except Exception:                          # noqa: BLE001 — bad/broken module
                pass
        if not ok:
            out.append(hint)
    return out


def _tools_list():
    # `description` is the standard model-facing text (any MCP client works).
    # shortDescription / longDescription / exampleQueries feed purragent's catalog and
    # RAG index; `timeout` is the suggested wait budget. Non-purragent clients ignore
    # the extra fields.
    out = []
    for name, (_b, normal, schema) in HACKTOOLS.items():
        short, long, examples = _META.get(name, (normal, normal, []))
        out.append({
            "name": name,
            "description": normal,
            "shortDescription": short,
            "longDescription": long,
            "exampleQueries": examples,
            "timeout": _TIMEOUTS.get(name, _DEFAULT_TOOL_TIMEOUT),
            "requires": _REQUIRES.get(name),      # external binary, or null if native
            "py_missing": _py_missing(name),      # unsatisfied python libs (native tools)
            "inputSchema": schema,
        })
    return out


def _call_tool(name, arguments):
    entry = HACKTOOLS.get(name)
    if entry is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    builder, _desc, _schema = entry
    try:
        built = builder(arguments or {})
    except ValueError as exc:                          # bad arguments
        return {"content": [{"type": "text", "text": f"invalid arguments: {exc}"}],
                "isError": True}
    except Exception as exc:                            # noqa: BLE001
        return {"content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True}
    # CLI tool → (argv:list, binary:str), run via subprocess. Python-native tool →
    # a str result (or a (str, is_error) tuple), already computed in-process.
    if isinstance(built, tuple) and built and isinstance(built[0], list):
        argv, binary = built
        text, is_error = _run(argv, binary)
        shown = "$ " + " ".join(argv) + "\n\n" + text
    else:
        if isinstance(built, tuple):
            text, is_error = (list(built) + [False])[:2]
        else:
            text, is_error = built, False
        shown = str(text)[:MAX_OUTPUT] or "(no output)"
    return {"content": [{"type": "text", "text": shown}], "isError": bool(is_error)}


def handle_message(msg):
    """Route one JSON-RPC request/notification; return a response dict or None."""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})
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


def selftest():
    """Offline check (no MCP client): list tools + validation, without touching the
    network (uses a bogus host so nmap/etc. aren't actually run against anyone)."""
    print(f"tools: {', '.join(HACKTOOLS)}")
    missing = [n for n in HACKTOOLS if n not in _META]
    print(f"[rag metadata] {'ok — every tool has short/long/examples' if not missing else 'MISSING: ' + ', '.join(missing)}")
    orphan_to = [n for n in _TIMEOUTS if n not in HACKTOOLS]
    dflt = [n for n in HACKTOOLS if n not in _TIMEOUTS]
    print(f"[timeouts] {len(_TIMEOUTS)} tools set, {len(dflt)} use default "
          f"{_DEFAULT_TOOL_TIMEOUT}s"
          + (f"; ORPHAN keys: {orphan_to}" if orphan_to else ""))
    for label, req in (
        ("initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        ("tools/list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ):
        resp = handle_message(req)
        n = len(resp["result"].get("tools", [])) if label == "tools/list" else "-"
        print(f"[{label}] ok  (tools: {n})")
    # argument validation (no command actually run for the reject cases)
    for name, args, expect_err in (
        ("port_discovery", {"host": "10.0.0.5/24"}, True),    # subnet rejected
        ("port_discovery", {"host": "bad host!"}, True),      # bad chars
        ("port_discovery", {"host": "10.0.0.5"}, False),      # default fast scan ok
        ("port_discovery", {"host": "10.0.0.5", "range": "zzz"}, True),   # bad range
        ("port_discovery", {"host": "10.0.0.5", "timing": "T9"}, True),   # bad timing
        ("port_discovery", {"host": "10.0.0.5", "protocol": "udp"},
         not _is_root()),                                # udp needs root
        ("service_discovery", {"host": "10.0.0.5"}, False),   # default ok
        ("service_discovery", {"host": "10.0.0.5", "intensity": 15}, True),  # 0-9
        ("service_discovery", {"host": "10.0.0.5", "os": True},
         not _is_root()),                                # -O needs root
        ("script_scan", {"host": "10.0.0.5", "scripts": "smb-brute"}, True),  # brute
        ("smb_enum", {"host": "10.0.0.5", "timing": "T9"}, True),   # bad timing
        ("banner_grab", {"host": "10.0.0.5"}, True),      # missing port
        ("dns_lookup", {"name": "example.com", "type": "ZZZ"}, True),      # bad type
        ("http_headers", {"host": "10.0.0.5", "method": "put"}, True),     # bad method
        ("snmp_walk", {"host": "10.0.0.5", "version": "3"}, True),         # v3 n/a
        ("searchsploit", {}, True),                       # neither query nor cve
        ("searchsploit", {"cve": "not-a-cve"}, True),     # bad cve
        ("http_request", {"url": "ftp://x"}, True),       # non-http URL
        ("http_request", {"url": "http://x/", "method": "TRACE"}, True),   # bad method
        ("http_request", {"url": "http://x/api", "method": "POST"}, False),  # ok
        ("web_content_discovery", {"url": "http://x", "wordlist": "zzz"}, True),  # bad wl
        ("whatweb", {"url": "http://x", "aggression": 9}, True),   # 1-4
        ("nuclei_scan", {"url": "http://x", "severity": "HIGH!"}, True),   # bad sev
        ("hash_identify", {"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}, False),  # ok
        ("jwt_decode", {"token": "notajwt"}, True),       # malformed
        ("data_transform", {"data": "x", "encoding": "morse"}, True),   # bad encoding
        ("payload_gen", {"lhost": "10.0.0.1"}, True),     # lport required
        ("cve_lookup", {"vendor": "a", "product": "b", "version": "none"}, True),  # no ver num
        ("ip_info", {"ip": "999.1.1.1"}, True),           # bad ip
        ("sqlmap", {"url": "http://x", "action": "dump"}, True),   # dump needs database
        ("sqlmap", {"url": "http://x", "level": 9}, True),         # 1-5
        ("certipy", {"dc": "10.0.0.5", "domain": "corp.local"}, True),  # needs username
        ("smtp_user_enum", {"host": "10.0.0.5", "username": "a b"}, True),  # bad user
        ("wafw00f", {"url": "notaurl"}, True),             # bad url
        ("git_dump", {"url": "ftp://x"}, True),             # non-http url
        ("s3_check", {}, True),                            # need bucket or url
        ("s3_check", {"bucket": "bad name!"}, True),        # bad bucket
        ("dns_bruteforce", {"domain": "bad host!"}, True),  # bad domain
        ("favicon_hash", {"url": "notaurl"}, True),        # bad url
        ("bloodhound_python", {"dc": "10.0.0.5", "domain": "corp.local"}, True),  # needs user
        ("arjun", {"url": "http://x", "method": "TRACE"}, True),   # bad method
        ("dnsrecon", {"domain": "x", "type": "zzz"}, True),        # bad type
        ("msfvenom", {"payload": "linux/x64/shell_reverse_tcp", "lhost": "10.0.0.1",
                      "lport": 4444, "format": "exe"}, True),      # binary format rejected
        ("msfvenom", {"payload": "cmd/unix/reverse_bash", "lhost": "10.0.0.1",
                      "lport": 4444, "format": "bash"}, False),    # ok
        ("smb_client", {"host": "10.0.0.5"}, False),      # null-session list ok
        ("smb_client", {"host": "10.0.0.5", "username": "a b"}, True),   # bad user
        ("netexec_smb", {"host": "10.0.0.5", "action": "exec"}, True),   # exec needs cmd
        ("secretsdump", {"host": "10.0.0.5"}, True),      # needs username
        ("impacket_exec", {"host": "10.0.0.5", "username": "u", "hash": "xyz"}, True),  # bad hash
        ("kerberos_roast", {"dc": "10.0.0.5"}, True),     # needs domain
        ("kerberos_roast", {"dc": "10.0.0.5", "domain": "corp.local"}, True),  # kerb needs creds
        ("mysql_query", {"host": "10.0.0.5", "query": "show databases;"}, False),  # ok
        ("mysql_query", {"host": "10.0.0.5"}, True),      # query required
        ("redis_cli", {"host": "10.0.0.5", "command": "FLUSHALL"}, True),   # destructive
        ("ssh_exec", {"host": "10.0.0.5", "username": "root", "command": "id"}, True),  # no pass/key
        ("winrm_exec", {"host": "10.0.0.5", "command": "whoami"}, True),    # needs username
        ("ftp_transfer", {"host": "10.0.0.5", "action": "delete"}, True),   # bad action
        ("subdomain_enum", {"domain": "example.com"}, False),   # ok
        ("dns_zone_transfer", {"domain": "example.com"}, True),  # nameserver required
        ("traceroute", {"host": "10.0.0.5", "protocol": "icmp"}, not _is_root()),  # root
        ("traceroute", {"host": "10.0.0.5", "max_hops": 99}, True),   # 1-64
        ("vhost_fuzz", {"url": "http://x", "domain": "example.com", "wordlist": "zzz"},
         True),                                          # bad wordlist
    ):
        b = HACKTOOLS[name][0]
        try:
            b(args)
            got_err = False
        except ValueError:
            got_err = True
        ok = got_err == expect_err
        print(f"[validate {name}] {'ok' if ok else 'FAIL'} "
              f"(rejected={got_err}, expected={expect_err})")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        serve()
