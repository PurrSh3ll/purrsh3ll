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
import re
import shutil
import subprocess
import sys

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "purr-hacktools"
SERVER_VERSION = "0.1.0"

DEFAULT_TIMEOUT = 120          # seconds per tool call
MAX_OUTPUT = 8000             # chars returned to the model (keeps replies readable)


# --------------------------------------------------------------------------- #
# Input validation + command runner
# --------------------------------------------------------------------------- #
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")     # ipv4 / ipv6 / hostname chars
_PORTS_RE = re.compile(r"^[0-9,\-]+$")           # 80  |  22,80,443  |  1-1024
_ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*\x07)")   # colour codes


def _req_host(args):
    """A single validated target host (no CIDR / subnet)."""
    host = (args.get("host") or "").strip()
    if not host:
        raise ValueError("`host` is required")
    if "/" in host:
        raise ValueError("`host` must be a single host, not a CIDR/subnet")
    if not _HOST_RE.match(host):
        raise ValueError("`host` has invalid characters")
    return host


def _port(args, default=None):
    p = args.get("port", default)
    if p is None:
        return None
    try:
        n = int(p)
    except (TypeError, ValueError):
        raise ValueError("`port` must be a number")
    if not 1 <= n <= 65535:
        raise ValueError("`port` must be 1-65535")
    return n


def _ports(args):
    p = (str(args.get("ports") or "")).replace(" ", "")
    if not p:
        return None
    if not _PORTS_RE.match(p):
        raise ValueError("`ports` must be like 80 or 22,80,443 or 1-1024")
    return p


def _word(args, key, required=True):
    v = (args.get(key) or "").strip()
    if not v and required:
        raise ValueError(f"`{key}` is required")
    return v


def _run(argv, binary, timeout=DEFAULT_TIMEOUT):
    """Run one argv (no shell), return (text, is_error). Reports a missing tool
    cleanly; keeps partial output on timeout."""
    if not shutil.which(binary):
        return (f"[not installed] '{binary}' is not on PATH — install it to use "
                "this tool.", True)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        partial = ((exc.stdout or "") + (exc.stderr or "")).strip()
        return (f"[timeout after {timeout}s]\n{partial[-MAX_OUTPUT:]}", False)
    except Exception as exc:                          # noqa: BLE001
        return (f"error running {binary}: {exc}", True)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    out = _ANSI_RE.sub("", out) or "(no output)"
    return (out[:MAX_OUTPUT], False)


_NSE_DENY = ("brute", "dos", "exploit")               # never run these NSE categories


# --------------------------------------------------------------------------- #
# Tool builders — each returns (argv, binary) or raises ValueError
# --------------------------------------------------------------------------- #
def _b_port_scan(a):
    host, ports = _req_host(a), _ports(a)
    argv = ["nmap", "-Pn", "-n", "--open", "-T4"]
    argv += (["-p", ports] if ports else ["--top-ports", "1000"])
    return argv + [host], "nmap"


def _b_service_scan(a):
    host, ports = _req_host(a), _ports(a)
    argv = ["nmap", "-sV", "-sC", "-Pn", "-n", "-T4"]
    argv += (["-p", ports] if ports else ["--top-ports", "1000"])
    return argv + [host], "nmap"


def _b_nse(a):
    host, ports = _req_host(a), _ports(a)
    scripts = _word(a, "scripts")
    low = scripts.lower()
    if any(bad in low for bad in _NSE_DENY):
        raise ValueError("brute / dos / exploit scripts are not allowed here")
    argv = ["nmap", "-sV", "-Pn", "-n", "-T4", "--script", scripts]
    argv += (["-p", ports] if ports else [])
    return argv + [host], "nmap"


def _b_http_headers(a):
    host = _req_host(a)
    port = _port(a)
    scheme = "https" if (a.get("tls") or port in (443, 8443)) else "http"
    netloc = f"{host}:{port}" if port else host
    return (["curl", "-sSI", "-k", "--max-time", "20", f"{scheme}://{netloc}/"],
            "curl")


def _b_ftp_anon(a):
    host = _req_host(a)
    port = _port(a, 21)
    return (["nmap", "-Pn", "-n", "-p", str(port), "--script", "ftp-anon", host],
            "nmap")


def _b_smb_enum(a):
    host = _req_host(a)
    return (["nmap", "-Pn", "-n", "-p", "139,445", "--script",
             "smb-os-discovery,smb-security-mode,smb2-security-mode,"
             "smb-enum-shares,smb-enum-users", host], "nmap")


def _b_snmp_walk(a):
    host = _req_host(a)
    community = _word(a, "community", required=False) or "public"
    if not re.match(r"^[A-Za-z0-9._-]+$", community):
        raise ValueError("`community` has invalid characters")
    return (["snmpwalk", "-v2c", "-c", community, "-t", "5", host], "snmpwalk")


def _b_dns(a):
    name = _word(a, "name")
    if not _HOST_RE.match(name):
        raise ValueError("`name` has invalid characters")
    rtype = (a.get("type") or "A").upper()
    if rtype not in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "ANY"):
        raise ValueError("unsupported record `type`")
    return (["dig", "+short", name, rtype], "dig")


def _b_ssl_cert(a):
    host = _req_host(a)
    port = _port(a, 443)
    return (["nmap", "-Pn", "-n", "-p", str(port), "--script", "ssl-cert", host],
            "nmap")


def _b_banner(a):
    host, port = _req_host(a), _port(a)
    if port is None:
        raise ValueError("`port` is required")
    return (["nmap", "-sV", "-Pn", "-n", "-p", str(port), "--script", "banner",
             host], "nmap")


def _b_searchsploit(a):
    query = _word(a, "query")            # colour auto-disables when output is piped
    return (["searchsploit"] + query.split(), "searchsploit")


def _b_whois(a):
    domain = _word(a, "domain")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    return (["whois", domain], "whois")


# name -> (builder, description, inputSchema, timeout)
_H = {"type": "string", "description": "Target host — a single IP or hostname "
      "(no CIDR/subnet)."}
_PORT = {"type": "integer", "description": "TCP port (1-65535)."}
_PORTS = {"type": "string", "description": "Ports, e.g. 80 or 22,80,443 or 1-1024. "
          "Omit for the top 1000."}

HACKTOOLS = {
    "port_scan": (
        _b_port_scan,
        "Discover open TCP ports on a host (nmap, top 1000 or the ports you give). "
        "Read-only enumeration.",
        {"type": "object", "properties": {"host": _H, "ports": _PORTS},
         "required": ["host"]}, 300),
    "service_scan": (
        _b_service_scan,
        "Fingerprint services/versions and run default NSE scripts (nmap -sV -sC) on "
        "a host's ports.",
        {"type": "object", "properties": {"host": _H, "ports": _PORTS},
         "required": ["host"]}, 300),
    "nse_scan": (
        _b_nse,
        "Run specific nmap NSE scripts against a host (e.g. 'http-title,http-methods' "
        "or 'smb-vuln-ms17-010'). brute/dos/exploit scripts are rejected.",
        {"type": "object", "properties": {
            "host": _H, "ports": _PORTS,
            "scripts": {"type": "string", "description": "Comma-separated NSE script "
                        "names or a safe wildcard like 'smb-vuln-*'."}},
         "required": ["host", "scripts"]}, 300),
    "http_headers": (
        _b_http_headers,
        "Fetch a web server's HTTP response headers (curl -I). Reveals server/tech "
        "banners and redirects.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "tls": {"type": "boolean", "description": "Use https (default: http, or "
                    "https on 443/8443)."}},
         "required": ["host"]}, 30),
    "ftp_anon": (
        _b_ftp_anon,
        "Check whether anonymous FTP login is allowed and list the root (nmap "
        "ftp-anon).",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host"]}, 60),
    "smb_enum": (
        _b_smb_enum,
        "Enumerate SMB with a null session: OS, signing, shares and users (nmap smb-* "
        "scripts).",
        {"type": "object", "properties": {"host": _H}, "required": ["host"]}, 120),
    "snmp_walk": (
        _b_snmp_walk,
        "Walk SNMP with a community string (default 'public') to dump system info.",
        {"type": "object", "properties": {
            "host": _H,
            "community": {"type": "string", "description": "SNMP community "
                          "(default: public)."}},
         "required": ["host"]}, 120),
    "dns_lookup": (
        _b_dns,
        "Resolve a DNS record (dig +short). Supports A/AAAA/MX/NS/TXT/CNAME/SOA/PTR.",
        {"type": "object", "properties": {
            "name": {"type": "string", "description": "Domain or host to resolve."},
            "type": {"type": "string", "description": "Record type (default A)."}},
         "required": ["name"]}, 30),
    "ssl_cert": (
        _b_ssl_cert,
        "Read a TLS service's certificate — subject, SANs, validity (nmap ssl-cert).",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host"]}, 60),
    "banner_grab": (
        _b_banner,
        "Grab the service banner on one port (nmap -sV + banner).",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host", "port"]}, 60),
    "searchsploit": (
        _b_searchsploit,
        "Search the local Exploit-DB copy for a product/version (searchsploit). "
        "Returns known public exploits — leads, not proof.",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "e.g. 'vsftpd 2.3.4' or "
                      "'apache 2.4'."}},
         "required": ["query"]}, 60),
    "whois": (
        _b_whois,
        "WHOIS registration info for a domain.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain name."}},
         "required": ["domain"]}, 30),
}


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing
# --------------------------------------------------------------------------- #
def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _tools_list():
    return [
        {"name": name, "description": desc, "inputSchema": schema}
        for name, (_b, desc, schema, _t) in HACKTOOLS.items()
    ]


def _call_tool(name, arguments):
    entry = HACKTOOLS.get(name)
    if entry is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    builder, _desc, _schema, timeout = entry
    try:
        argv, binary = builder(arguments or {})
    except ValueError as exc:                          # bad arguments
        return {"content": [{"type": "text", "text": f"invalid arguments: {exc}"}],
                "isError": True}
    except Exception as exc:                            # noqa: BLE001
        return {"content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True}
    text, is_error = _run(argv, binary, timeout)
    shown = "$ " + " ".join(argv) + "\n\n" + text
    return {"content": [{"type": "text", "text": shown}], "isError": is_error}


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
    for label, req in (
        ("initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        ("tools/list", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ):
        resp = handle_message(req)
        n = len(resp["result"].get("tools", [])) if label == "tools/list" else "-"
        print(f"[{label}] ok  (tools: {n})")
    # argument validation (no command actually run for the reject cases)
    for name, args, expect_err in (
        ("port_scan", {"host": "10.0.0.5/24"}, True),     # subnet rejected
        ("port_scan", {"host": "bad host!"}, True),       # bad chars
        ("nse_scan", {"host": "10.0.0.5", "scripts": "smb-brute"}, True),  # brute
        ("banner_grab", {"host": "10.0.0.5"}, True),      # missing port
        ("dns_lookup", {"name": "example.com", "type": "ZZZ"}, True),      # bad type
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
