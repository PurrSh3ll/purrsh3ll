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


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:                             # non-POSIX
        return False


_URL_RE = re.compile(r"^https?://[^\s]+$", re.I)


def _req_url(a, key="url"):
    """A validated http(s) URL (required)."""
    url = (a.get(key) or "").strip()
    if not url:
        raise ValueError(f"`{key}` is required")
    if not _URL_RE.match(url) or re.search(r"[\x00-\x1f]", url):
        raise ValueError(f"`{key}` must be an http(s) URL")
    return url


def _no_ctrl(v, key):
    if re.search(r"[\x00-\x1f]", v):
        raise ValueError(f"`{key}` has control characters")
    return v


# Preset wordlists for content discovery → the first path that exists on the box.
_WORDLISTS = {
    "common": ["/usr/share/seclists/Discovery/Web-Content/common.txt",
               "/usr/share/wordlists/dirb/common.txt"],
    "medium": ["/usr/share/seclists/Discovery/Web-Content/"
               "directory-list-2.3-medium.txt"],
    "big": ["/usr/share/seclists/Discovery/Web-Content/big.txt",
            "/usr/share/wordlists/dirb/big.txt"],
    "raft": ["/usr/share/seclists/Discovery/Web-Content/"
             "raft-medium-directories.txt"],
}


def _resolve_wordlist(name):
    for p in _WORDLISTS.get(name, []):
        if os.path.exists(p):
            return p
    return None


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


def _nmap_tuning(a):
    """Shared nmap knobs for every scan tool: timing (T0-T5) and whether to ping
    first (host_discovery=false → -Pn). Returns the flag list to splice into argv."""
    timing = (a.get("timing") or "T4").upper()
    if not re.match(r"^T[0-5]$", timing):
        raise ValueError("`timing` must be T0-T5")
    flags = ["-" + timing]
    if not bool(a.get("host_discovery")):
        flags.append("-Pn")                            # assume the host is up
    return flags


# --------------------------------------------------------------------------- #
# Tool builders — each returns (argv, binary) or raises ValueError
# --------------------------------------------------------------------------- #
_RANGE_PORTS = {"fast": ["--top-ports", "1000"], "top100": ["--top-ports", "100"],
                "low": ["-p", "1-32767"], "high": ["-p", "32768-65535"],
                "full": ["-p-"]}


def _b_port_discovery(a):
    host = _req_host(a)
    ports = _ports(a)
    rng = (a.get("range") or "fast").lower()
    proto = (a.get("protocol") or "tcp").lower()
    timing = (a.get("timing") or "T4").upper()
    host_disc = bool(a.get("host_discovery"))
    if rng not in _RANGE_PORTS:
        raise ValueError("`range` must be fast/top100/low/high/full")
    if proto not in ("tcp", "udp", "both"):
        raise ValueError("`protocol` must be tcp/udp/both")
    if not re.match(r"^T[0-5]$", timing):
        raise ValueError("`timing` must be T0-T5")
    root = _is_root()
    if proto in ("udp", "both") and not root:
        raise ValueError("udp/both scans need root — run as root or use "
                         "protocol=tcp")
    scan_flags = {"tcp": ["-sS" if root else "-sT"], "udp": ["-sU"],
                  "both": ["-sS", "-sU"]}[proto]
    argv = ["nmap"] + scan_flags + ["-n", "--open", "-" + timing]
    if not host_disc:
        argv.append("-Pn")                            # assume the host is up
    argv += (["-p", ports] if ports else _RANGE_PORTS[rng])   # explicit ports win
    argv.append(host)
    slow = rng == "full" or proto in ("udp", "both")
    return argv, "nmap", (900 if slow else 300)


def _b_service_discovery(a):
    host = _req_host(a)
    ports = _ports(a)
    proto = (a.get("protocol") or "tcp").lower()
    timing = (a.get("timing") or "T4").upper()
    host_disc = bool(a.get("host_discovery"))
    scripts = a.get("scripts", True)
    os_det = bool(a.get("os"))
    intensity = a.get("intensity")
    if proto not in ("tcp", "udp", "both"):
        raise ValueError("`protocol` must be tcp/udp/both")
    if not re.match(r"^T[0-5]$", timing):
        raise ValueError("`timing` must be T0-T5")
    root = _is_root()
    if proto in ("udp", "both") and not root:
        raise ValueError("udp/both scans need root — run as root or use "
                         "protocol=tcp")
    if os_det and not root:
        raise ValueError("os detection (-O) needs root — run as root or set os=false")
    argv = ["nmap", "-sV"]
    argv += {"tcp": ["-sS" if root else "-sT"], "udp": ["-sU"],
             "both": ["-sS", "-sU"]}[proto]
    if scripts:
        argv.append("-sC")                            # default NSE scripts
    if os_det:
        argv.append("-O")
    if intensity is not None:
        try:
            iv = int(intensity)
        except (TypeError, ValueError):
            raise ValueError("`intensity` must be 0-9")
        if not 0 <= iv <= 9:
            raise ValueError("`intensity` must be 0-9")
        argv += ["--version-intensity", str(iv)]
    argv += ["-n", "--open", "-" + timing]
    if not host_disc:
        argv.append("-Pn")
    argv += (["-p", ports] if ports else ["--top-ports", "1000"])
    argv.append(host)
    slow = proto in ("udp", "both") or os_det
    return argv, "nmap", (900 if slow else 300)


def _b_script_scan(a):
    host, ports = _req_host(a), _ports(a)
    scripts = _word(a, "scripts")
    if any(bad in scripts.lower() for bad in _NSE_DENY):
        raise ValueError("brute / dos / exploit scripts are not allowed here")
    argv = ["nmap", "-sV", "-n"] + _nmap_tuning(a) + ["--script", scripts]
    argv += (["-p", ports] if ports else [])
    return argv + [host], "nmap"


def _b_http_headers(a):
    host = _req_host(a)
    port = _port(a)
    scheme = "https" if (a.get("tls") or port in (443, 8443)) else "http"
    netloc = f"{host}:{port}" if port else host
    path = (a.get("path") or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    if re.search(r"[\s\x00-\x1f]", path):
        raise ValueError("`path` has invalid characters")
    method = (a.get("method") or "head").lower()
    if method not in ("head", "get"):
        raise ValueError("`method` must be head or get")
    argv = ["curl", "-sS", "-k", "--max-time", "20"]
    argv += ["-I"] if method == "head" else ["-D", "-", "-o", os.devnull]
    if a.get("follow_redirects"):
        argv.append("-L")
    ua = (a.get("user_agent") or "").strip()
    if ua:
        if re.search(r"[\x00-\x1f]", ua):
            raise ValueError("`user_agent` has control characters")
        argv += ["-A", ua]
    return argv + [f"{scheme}://{netloc}{path}"], "curl"


def _b_ftp_anon(a):
    host = _req_host(a)
    port = _port(a, 21)
    return (["nmap", "-n"] + _nmap_tuning(a)
            + ["-p", str(port), "--script", "ftp-anon", host], "nmap")


def _b_smb_enum(a):
    host = _req_host(a)
    return (["nmap", "-n"] + _nmap_tuning(a)
            + ["-p", "139,445", "--script",
               "smb-os-discovery,smb-security-mode,smb2-security-mode,"
               "smb-enum-shares,smb-enum-users", host], "nmap")


def _b_snmp_walk(a):
    host = _req_host(a)
    community = _word(a, "community", required=False) or "public"
    if not re.match(r"^[A-Za-z0-9._-]+$", community):
        raise ValueError("`community` has invalid characters")
    version = str(a.get("version") or "2c").lower()
    if version not in ("1", "2c"):
        raise ValueError("`version` must be 1 or 2c")
    port = _port(a, 161)
    oid = (a.get("oid") or "").strip()
    if oid and not re.match(r"^[A-Za-z0-9._:-]+$", oid):
        raise ValueError("`oid` has invalid characters")
    argv = ["snmpwalk", "-v1" if version == "1" else "-v2c", "-c", community,
            "-t", "5", f"{host}:{port}"]
    if oid:
        argv.append(oid)                              # walk a specific subtree
    return argv, "snmpwalk"


def _b_dns(a):
    name = _word(a, "name")
    if not _HOST_RE.match(name):
        raise ValueError("`name` has invalid characters")
    rtype = (a.get("type") or "A").upper()
    if rtype not in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "ANY"):
        raise ValueError("unsupported record `type`")
    argv = ["dig", "+short"]
    server = (a.get("server") or "").strip()
    if server:                                        # query a specific resolver
        if not _HOST_RE.match(server):
            raise ValueError("`server` has invalid characters")
        argv.append("@" + server)
    return argv + [name, rtype], "dig"


def _b_ssl_cert(a):
    host = _req_host(a)
    port = _port(a, 443)
    return (["nmap", "-n"] + _nmap_tuning(a)
            + ["-p", str(port), "--script", "ssl-cert", host], "nmap")


def _b_banner(a):
    host, port = _req_host(a), _port(a)
    if port is None:
        raise ValueError("`port` is required")
    return (["nmap", "-sV", "-n"] + _nmap_tuning(a)
            + ["-p", str(port), "--script", "banner", host], "nmap")


def _b_searchsploit(a):
    query = (a.get("query") or "").strip()
    cve = (a.get("cve") or "").strip()
    if not query and not cve:
        raise ValueError("provide `query` or `cve`")
    argv = ["searchsploit"]                # colour auto-disables when output is piped
    if a.get("title"):
        argv.append("-t")                             # match the title only
    if cve:
        if not re.match(r"^(CVE-)?\d{4}-\d{3,7}$", cve, re.I):
            raise ValueError("`cve` must look like CVE-2017-0144 or 2017-0144")
        argv += ["--cve", cve.upper().replace("CVE-", "")]
    if query:
        argv += query.split()
    return argv, "searchsploit"


def _b_whois(a):
    domain = _word(a, "domain")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    argv = ["whois"]
    server = (a.get("server") or "").strip()
    if server:                                        # query a specific whois server
        if not _HOST_RE.match(server):
            raise ValueError("`server` has invalid characters")
        argv += ["-h", server]
    return argv + [domain], "whois"


# ── web batch ─────────────────────────────────────────────────────────────────
def _b_http_request(a):
    url = _req_url(a)
    method = (a.get("method") or "GET").upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
        raise ValueError("unsupported `method`")
    argv = ["curl", "-sS", "-i", "-k", "--max-time", "30", "-X", method]
    for h in (a.get("headers") or []):
        argv += ["-H", _no_ctrl(str(h), "headers")]
    cookie = (a.get("cookie") or "").strip()
    if cookie:
        argv += ["-b", _no_ctrl(cookie, "cookie")]
    user = (a.get("username") or "").strip()
    if user:                                          # HTTP basic auth
        argv += ["-u", f"{user}:{a.get('password') or ''}"]
    bearer = (a.get("bearer") or "").strip()
    if bearer:
        argv += ["-H", "Authorization: Bearer " + _no_ctrl(bearer, "bearer")]
    data = a.get("data")
    if data not in (None, ""):
        argv += ["--data", str(data)]
    if a.get("follow_redirects"):
        argv.append("-L")
    ua = (a.get("user_agent") or "").strip()
    if ua:
        argv += ["-A", _no_ctrl(ua, "user_agent")]
    return argv + [url], "curl"


def _b_web_content(a):
    url = _req_url(a)
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    name = (a.get("wordlist") or "common").lower()
    if name not in _WORDLISTS:
        raise ValueError("`wordlist` must be common/medium/big/raft")
    wl = _resolve_wordlist(name)
    if not wl:
        raise ValueError(f"wordlist '{name}' not found — install seclists or dirb")
    try:
        threads = int(a.get("threads", 40))
    except (TypeError, ValueError):
        raise ValueError("`threads` must be a number")
    if not 1 <= threads <= 100:
        raise ValueError("`threads` must be 1-100")
    argv = ["ffuf", "-u", url, "-w", wl, "-t", str(threads), "-s",
            "-mc", "200,204,301,302,307,401,403,405"]
    exts = (a.get("extensions") or "").strip()
    if exts:
        if not re.match(r"^[A-Za-z0-9,.]+$", exts):
            raise ValueError("`extensions` must be like php,txt,html")
        argv += ["-e", exts]
    return argv, "ffuf", 600


def _b_whatweb(a):
    url = _req_url(a)
    argv = ["whatweb", "--color=never", "--no-errors"]
    agg = a.get("aggression")
    if agg is not None:
        try:
            av = int(agg)
        except (TypeError, ValueError):
            raise ValueError("`aggression` must be 1-4")
        if not 1 <= av <= 4:
            raise ValueError("`aggression` must be 1-4")
        argv += ["-a", str(av)]
    return argv + [url], "whatweb"


def _b_nikto(a):
    host = _req_host(a)
    port = _port(a, 80)
    argv = ["nikto", "-ask", "no", "-h", host, "-p", str(port)]
    if a.get("tls") or port in (443, 8443):
        argv.append("-ssl")
    return argv, "nikto", 900


def _b_nuclei(a):
    url = _req_url(a)
    argv = ["nuclei", "-u", url, "-silent", "-nc"]
    sev = (a.get("severity") or "").strip().lower()
    if sev:
        if not re.match(r"^[a-z,]+$", sev):
            raise ValueError("`severity` must be like low,medium,high,critical")
        argv += ["-severity", sev]
    tags = (a.get("tags") or "").strip().lower()
    if tags:
        if not re.match(r"^[a-z0-9,_-]+$", tags):
            raise ValueError("`tags` has invalid characters")
        argv += ["-tags", tags]
    return argv, "nuclei", 900


# name -> (builder, description, inputSchema, timeout)
_H = {"type": "string", "description": "Target host — a single IP or hostname "
      "(no CIDR/subnet)."}
_PORT = {"type": "integer", "description": "TCP port (1-65535)."}
_PORTS = {"type": "string", "description": "Ports, e.g. 80 or 22,80,443 or 1-1024. "
          "Omit for the top 1000."}
# shared tuning knobs, on every nmap-based scan tool:
_TIMING = {"type": "string", "description": "nmap timing T0-T5 (default T4; lower is "
           "slower/stealthier for filtered or laggy hosts)."}
_HOSTDISC = {"type": "boolean", "description": "false (default) uses -Pn (assume up); "
             "true lets nmap ping the host first."}

HACKTOOLS = {
    "port_discovery": (
        _b_port_discovery,
        "Discover open ports on a host. Give just `host` for a fast top-1000 TCP scan; "
        "the options let you widen the range (low/high/full), scan UDP, slow the "
        "timing, or enable host discovery when -Pn is being dropped. Read-only.",
        {"type": "object", "properties": {
            "host": _H,
            "range": {"type": "string", "description": "Port set: fast (top 1000, "
                      "default) · top100 · low (1-32767) · high (32768-65535) · "
                      "full (1-65535)."},
            "ports": {"type": "string", "description": "Explicit ports (e.g. "
                      "22,80,443 or 1-1024) — overrides `range`."},
            "protocol": {"type": "string", "description": "tcp (default) · udp · "
                         "both. udp/both need root."},
            "timing": {"type": "string", "description": "nmap timing T0-T5 (default "
                       "T4; lower is slower/stealthier for filtered or laggy hosts)."},
            "host_discovery": {"type": "boolean", "description": "false (default) "
                               "uses -Pn (assume up); true lets nmap ping first."}},
         "required": ["host"]}, 300),
    "service_discovery": (
        _b_service_discovery,
        "Fingerprint the services/versions behind a host's open ports (nmap -sV, plus "
        "default -sC scripts). Give just `host`; options let you pick ports, scan "
        "UDP, toggle scripts, tune version intensity, add OS detection, or slow the "
        "timing. Usually run on the open ports from port_discovery.",
        {"type": "object", "properties": {
            "host": _H,
            "ports": {"type": "string", "description": "Ports to fingerprint (e.g. "
                      "22,80,443). Omit for the top 1000 — usually the open ports "
                      "from port_discovery."},
            "protocol": {"type": "string", "description": "tcp (default) · udp · "
                         "both. udp/both need root."},
            "scripts": {"type": "boolean", "description": "Run default NSE scripts "
                        "-sC (default true). false = -sV only (faster/quieter)."},
            "intensity": {"type": "integer", "description": "Version-probe intensity "
                          "0-9 (nmap default 7; lower is faster/lighter)."},
            "os": {"type": "boolean", "description": "Also detect the OS (-O, needs "
                   "root). Default false."},
            "timing": {"type": "string", "description": "nmap timing T0-T5 (default "
                       "T4; lower is slower/stealthier)."},
            "host_discovery": {"type": "boolean", "description": "false (default) "
                               "uses -Pn (assume up); true lets nmap ping first."}},
         "required": ["host"]}, 300),
    "script_scan": (
        _b_script_scan,
        "Run specific nmap NSE scripts against a host (e.g. 'http-title,http-methods' "
        "or 'smb-vuln-ms17-010'). brute/dos/exploit scripts are rejected.",
        {"type": "object", "properties": {
            "host": _H, "ports": _PORTS,
            "scripts": {"type": "string", "description": "Comma-separated NSE script "
                        "names or a safe wildcard like 'smb-vuln-*'."},
            "timing": _TIMING, "host_discovery": _HOSTDISC},
         "required": ["host", "scripts"]}, 300),
    "http_headers": (
        _b_http_headers,
        "Fetch a web server's HTTP response headers (curl). Reveals server/tech "
        "banners, cookies and redirects; can target a path and follow redirects.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "tls": {"type": "boolean", "description": "Use https (default: http, or "
                    "https on 443/8443)."},
            "path": {"type": "string", "description": "Request path (default '/'), "
                     "e.g. /admin or /api."},
            "method": {"type": "string", "description": "head (default, -I) or get "
                       "(headers of a GET)."},
            "follow_redirects": {"type": "boolean", "description": "Follow 3xx "
                                 "redirects (-L). Default false."},
            "user_agent": {"type": "string", "description": "Custom User-Agent "
                           "header."}},
         "required": ["host"]}, 30),
    "ftp_anon": (
        _b_ftp_anon,
        "Check whether anonymous FTP login is allowed and list the root (nmap "
        "ftp-anon).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host"]}, 60),
    "smb_enum": (
        _b_smb_enum,
        "Enumerate SMB with a null session: OS, signing, shares and users (nmap smb-* "
        "scripts).",
        {"type": "object", "properties": {
            "host": _H, "timing": _TIMING, "host_discovery": _HOSTDISC},
         "required": ["host"]}, 120),
    "snmp_walk": (
        _b_snmp_walk,
        "Walk SNMP with a community string (default 'public') to dump system info. "
        "Can target a starting OID subtree and pick the SNMP version/port.",
        {"type": "object", "properties": {
            "host": _H,
            "community": {"type": "string", "description": "SNMP community "
                          "(default: public)."},
            "version": {"type": "string", "description": "SNMP version: 1 or 2c "
                        "(default 2c)."},
            "oid": {"type": "string", "description": "Start OID/subtree, e.g. "
                    "1.3.6.1.2.1.1 (system). Omit to walk from the top."},
            "port": {"type": "integer", "description": "SNMP UDP port (default 161)."}},
         "required": ["host"]}, 120),
    "dns_lookup": (
        _b_dns,
        "Resolve a DNS record (dig +short). Supports A/AAAA/MX/NS/TXT/CNAME/SOA/PTR "
        "and can query a specific resolver.",
        {"type": "object", "properties": {
            "name": {"type": "string", "description": "Domain or host to resolve."},
            "type": {"type": "string", "description": "Record type (default A)."},
            "server": {"type": "string", "description": "Resolver to query (@server), "
                       "e.g. the target's own DNS. Default: system resolver."}},
         "required": ["name"]}, 30),
    "ssl_cert": (
        _b_ssl_cert,
        "Read a TLS service's certificate — subject, SANs, validity (nmap ssl-cert).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host"]}, 60),
    "banner_grab": (
        _b_banner,
        "Grab the service banner on one port (nmap -sV + banner).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host", "port"]}, 60),
    "searchsploit": (
        _b_searchsploit,
        "Search the local Exploit-DB copy (searchsploit) by product/version, by CVE, "
        "or title-only. Returns known public exploits — leads, not proof.",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "e.g. 'vsftpd 2.3.4' or "
                      "'apache 2.4'. Optional if `cve` is given."},
            "cve": {"type": "string", "description": "Search by CVE, e.g. "
                    "CVE-2021-3156 or 2021-3156."},
            "title": {"type": "boolean", "description": "Match the exploit title only "
                      "(-t) — fewer false matches. Default false."}},
         "required": []}, 60),
    "whois": (
        _b_whois,
        "WHOIS registration info for a domain or IP; can target a specific WHOIS "
        "server.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain name or IP."},
            "server": {"type": "string", "description": "WHOIS server to query (-h). "
                       "Default: whois picks it."}},
         "required": ["domain"]}, 30),
    "http_request": (
        _b_http_request,
        "Make an arbitrary HTTP request with curl and return the status, headers and "
        "body. Set method, headers, body, cookie, basic-auth or a bearer token — good "
        "for probing endpoints and testing APIs with credentials from the engagement. "
        "(Credentials are passed on the command line.)",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Full http(s) URL, e.g. "
                    "http://10.0.0.5:8080/api/users."},
            "method": {"type": "string", "description": "GET (default), POST, PUT, "
                       "DELETE, HEAD, OPTIONS, PATCH."},
            "headers": {"type": "array", "items": {"type": "string"},
                        "description": "Extra headers, each 'Name: value'."},
            "data": {"type": "string", "description": "Request body (for POST/PUT)."},
            "cookie": {"type": "string", "description": "Cookie header value."},
            "username": {"type": "string", "description": "HTTP basic-auth username."},
            "password": {"type": "string", "description": "HTTP basic-auth password."},
            "bearer": {"type": "string", "description": "Bearer token (Authorization "
                       "header)."},
            "follow_redirects": {"type": "boolean", "description": "Follow 3xx (-L)."},
            "user_agent": {"type": "string", "description": "Custom User-Agent."}},
         "required": ["url"]}, 40),
    "web_content_discovery": (
        _b_web_content,
        "Brute-force web directories and files with ffuf against a URL (put FUZZ where "
        "the word goes, or just give the base URL). Picks a preset wordlist and "
        "reports found paths with their status codes.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Base URL (FUZZ appended) or a "
                    "URL containing FUZZ, e.g. http://host/FUZZ."},
            "wordlist": {"type": "string", "description": "Preset: common (default), "
                         "medium, big, raft."},
            "extensions": {"type": "string", "description": "Extensions to append, "
                           "e.g. php,txt,html."},
            "threads": {"type": "integer", "description": "Concurrency 1-100 "
                        "(default 40)."}},
         "required": ["url"]}, 600),
    "whatweb": (
        _b_whatweb,
        "Fingerprint a website's stack — server, CMS, frameworks, libraries and their "
        "versions (whatweb).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Full http(s) URL."},
            "aggression": {"type": "integer", "description": "Aggression 1 (passive) "
                           "to 4 (heavy). Default whatweb's."}},
         "required": ["url"]}, 120),
    "nikto_scan": (
        _b_nikto,
        "Scan a web server for known issues, dangerous files and misconfigurations "
        "(nikto). Noisy — an active vulnerability scan.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "tls": {"type": "boolean", "description": "Use https (auto on 443/8443)."}},
         "required": ["host"]}, 900),
    "nuclei_scan": (
        _b_nuclei,
        "Run nuclei's community templates against a URL to find CVEs, exposures and "
        "misconfigurations. Filter by severity or tags to keep it focused.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Full http(s) URL, e.g. "
                    "http://10.0.0.5."},
            "severity": {"type": "string", "description": "Comma list: info,low,"
                         "medium,high,critical."},
            "tags": {"type": "string", "description": "Template tags, e.g. cve,"
                     "exposure,wordpress."}},
         "required": ["url"]}, 900),
}


# RAG metadata for purragent's client-side tool retriever: a one-line `short` for the
# catalog, a keyword/scenario-heavy `long` used to build the embedding index, and
# `examples` of user phrasings the tool answers (query-to-query matching). Emitted as
# shortDescription / longDescription / exampleQueries; plain MCP clients ignore them.
# name -> (short, long, [examples])
_META = {
    "port_discovery": (
        "Discover open TCP/UDP ports on a host.",
        "Port scanning and port discovery with nmap: find which ports are open on a "
        "single host. Presets fast (top 1000), top100, low (1-32767), high, full "
        "(1-65535); TCP SYN/connect or UDP; adjustable timing T0-T5 for filtered, "
        "firewalled or slow hosts; -Pn host-discovery toggle. The first recon step "
        "before service detection. Keywords: nmap, scan, open ports, port sweep, SYN "
        "scan, connect scan, UDP scan, firewall, filtered.",
        ["scan for open ports on 10.0.0.5", "what ports are open on the target",
         "do a full port scan", "check for open UDP ports", "port discovery on this host"]),
    "service_discovery": (
        "Fingerprint the services and versions on a host's ports.",
        "Service and version detection with nmap -sV plus default -sC NSE scripts: "
        "identify the software and version behind each open port. Optional OS "
        "detection (-O), UDP, version intensity, timing. Run after port_discovery on "
        "the open ports. Keywords: nmap -sV -sC, banner, version detection, "
        "fingerprint, service enumeration, OS detection, product version.",
        ["what service is running on port 80", "detect versions on the open ports",
         "fingerprint the services on 10.0.0.5", "run an nmap service/version scan",
         "identify the software and versions"]),
    "script_scan": (
        "Run specific nmap NSE scripts against a host.",
        "Targeted nmap NSE script scan: run named scripts such as http-title, "
        "http-methods, smb-vuln-ms17-010, ssl-enum-ciphers, or a safe wildcard like "
        "smb-vuln-*. For vulnerability detection and deeper protocol enumeration. "
        "brute/dos/exploit categories rejected. Keywords: nmap --script, NSE, vuln "
        "scan, smb-vuln, ms17-010, eternalblue detection, http-enum, ssl ciphers.",
        ["run smb-vuln-ms17-010 on the host", "check for eternalblue",
         "run nmap nse http scripts on port 80", "enumerate ssl ciphers",
         "scan with a specific nmap script"]),
    "http_headers": (
        "Fetch a web server's HTTP response headers.",
        "HTTP header grab with curl: reveal Server / X-Powered-By tech banners, "
        "cookies, security headers and redirects. Target a path (/admin, /api), HEAD "
        "or GET, follow redirects, set a custom User-Agent, http or https. Web recon. "
        "Keywords: curl -I, http headers, server banner, web technology, X-Powered-By, "
        "redirect, HSTS, set-cookie.",
        ["get the http headers of the web server", "what web server runs on port 80",
         "check headers at /admin", "follow redirects and show the headers",
         "curl the target's website headers"]),
    "ftp_anon": (
        "Check anonymous FTP login and list the root.",
        "Anonymous FTP check with nmap ftp-anon: test whether anonymous login works "
        "and list the FTP root directory — a quick anonymous foothold. Keywords: ftp, "
        "anonymous login, ftp-anon, port 21, anon ftp, directory listing.",
        ["is anonymous ftp allowed on 10.0.0.5", "check ftp anonymous login",
         "list the ftp root directory", "test anonymous ftp on port 21"]),
    "smb_enum": (
        "Enumerate SMB via null session: OS, shares, users.",
        "SMB and Windows-shares enumeration with nmap smb-* scripts over a null "
        "session: OS discovery, SMB signing / security mode, shares and users. "
        "Windows/AD recon. Keywords: smb, cifs, netbios, port 445, port 139, null "
        "session, shares, smb-enum-shares, smb-enum-users, smb-os-discovery, windows.",
        ["enumerate smb shares on 10.0.0.5", "list smb users",
         "what OS via smb", "smb null-session enumeration", "check windows shares on 445"]),
    "snmp_walk": (
        "Walk SNMP to dump a host's system info.",
        "SNMP enumeration with snmpwalk: dump system info, interfaces, processes or "
        "users depending on the OID subtree. Community string (default public), SNMP "
        "v1/v2c, custom port, start OID. Keywords: snmp, snmpwalk, community string, "
        "public, port 161, MIB, OID, udp enumeration, system description.",
        ["walk snmp on 10.0.0.5", "snmp enumeration with community public",
         "dump the snmp system info", "snmpwalk the target", "read snmp oid 1.3.6.1.2.1.1"]),
    "dns_lookup": (
        "Resolve a DNS record (A/MX/NS/TXT/PTR/…).",
        "DNS resolution with dig: look up A/AAAA/MX/NS/TXT/CNAME/SOA/PTR records, "
        "optionally against a specific resolver (@server) such as the target's own "
        "DNS. DNS recon. Keywords: dns, dig, nslookup, resolve, mx record, name "
        "server, txt record, reverse dns, ptr, resolver.",
        ["resolve example.com", "what are the MX records for the domain",
         "look up the NS records", "dig the A record via 8.8.8.8",
         "reverse dns lookup for the ip"]),
    "ssl_cert": (
        "Read a TLS service's certificate (subject, SANs).",
        "TLS/SSL certificate reader with nmap ssl-cert: show subject, SAN hostnames, "
        "issuer and validity — good for discovering extra hostnames / vhosts and "
        "self-signed or expired certs. Keywords: tls, ssl, certificate, x509, SAN, "
        "subject alternative name, https, port 443, cert expiry, self-signed, issuer.",
        ["read the ssl certificate on port 443", "what hostnames are in the tls cert",
         "check the certificate subject and SANs", "get the https certificate details"]),
    "banner_grab": (
        "Grab the service banner on one port.",
        "Single-port banner grab with nmap -sV plus the banner script: read the raw "
        "service banner/version on a chosen port for quick identification. Keywords: "
        "banner grab, service banner, version, nmap banner, netcat banner, port "
        "fingerprint, greeting.",
        ["grab the banner on port 22", "what banner does port 8080 show",
         "identify the service on this port", "read the service banner"]),
    "searchsploit": (
        "Search Exploit-DB for a product/version or CVE.",
        "Local Exploit-DB search with searchsploit: find known public exploits by "
        "product/version (e.g. 'vsftpd 2.3.4'), by CVE (--cve), or title-only. Turns "
        "a detected version into exploit leads. Offline; leads, not proof. Keywords: "
        "searchsploit, exploit-db, public exploit, CVE, PoC, known exploit, edb-id.",
        ["search exploits for vsftpd 2.3.4", "any public exploit for apache 2.4",
         "searchsploit CVE-2021-3156", "find exploit-db entries for this version"]),
    "whois": (
        "WHOIS registration info for a domain or IP.",
        "WHOIS lookup for a domain or IP, optionally against a specific WHOIS server "
        "(-h): registrar, organisation, contacts, and netblock/ASN for IPs. OSINT / "
        "recon. Keywords: whois, registration, registrar, domain owner, netblock, "
        "ASN, ip whois, abuse contact.",
        ["whois for example.com", "who owns this domain", "whois the ip address",
         "registration info for the domain"]),
    "http_request": (
        "Make an arbitrary HTTP request (method, headers, body, auth).",
        "Arbitrary HTTP request with curl: choose the method (GET/POST/PUT/DELETE/…), "
        "add headers, a body, a cookie, HTTP basic-auth or a bearer token, follow "
        "redirects. Probe endpoints, test REST/GraphQL APIs, replay a request with "
        "credentials from the engagement, check an authenticated page. Keywords: curl, "
        "http request, POST, api, rest, bearer token, basic auth, cookie, header, "
        "authenticated request, endpoint.",
        ["send a POST to the login endpoint", "make an authenticated GET with this cookie",
         "call the api with a bearer token", "test the endpoint with basic auth",
         "curl this url with a custom header"]),
    "web_content_discovery": (
        "Brute-force web directories and files (ffuf).",
        "Web content discovery / directory and file brute-force with ffuf: find hidden "
        "paths, admin panels, backups and endpoints on a web server using a preset "
        "wordlist, optional extensions, reporting status codes. Keywords: ffuf, "
        "gobuster, dirb, directory brute force, content discovery, fuzzing, hidden "
        "files, admin panel, dirbuster, wordlist. Not an auth/password brute-force.",
        ["find hidden directories on the website", "dir brute force the web server",
         "discover admin panels and backups", "fuzz for hidden php files",
         "run ffuf content discovery on the url"]),
    "whatweb": (
        "Fingerprint a website's stack (server, CMS, frameworks).",
        "Website technology fingerprinting with whatweb: detect the web server, CMS "
        "(WordPress/Joomla/Drupal), frameworks, languages, JS libraries and versions. "
        "Web recon. Keywords: whatweb, web technology, fingerprint, cms detection, "
        "wappalyzer, framework, server header, stack detection.",
        ["what technologies does this website use", "fingerprint the web stack",
         "detect the CMS on the site", "identify the web framework and versions"]),
    "nikto_scan": (
        "Scan a web server for known issues and misconfigs.",
        "Web server vulnerability scan with nikto: check for dangerous files, outdated "
        "software, default files, headers and common misconfigurations. Noisy active "
        "scan. Keywords: nikto, web vulnerability scanner, misconfiguration, dangerous "
        "files, outdated server, default files, web audit.",
        ["run nikto against the web server", "scan the website for vulnerabilities",
         "check the web server for misconfigurations", "nikto scan on port 8080"]),
    "nuclei_scan": (
        "Run nuclei templates for CVEs/exposures on a URL.",
        "Template-based vulnerability scanning with nuclei: match a URL against the "
        "community templates for CVEs, exposures, misconfigurations, default creds and "
        "takeovers. Filter by severity or tags. Keywords: nuclei, templates, CVE scan, "
        "exposure, misconfiguration, vulnerability scanner, takeover, default "
        "credentials, web vuln.",
        ["run nuclei against the target url", "scan for CVEs with nuclei",
         "check for known web vulnerabilities", "nuclei high and critical only",
         "find exposures on the website"]),
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
    # `description` is the standard model-facing text (any MCP client works).
    # shortDescription / longDescription / exampleQueries are extra fields purragent's
    # client reads for its catalog and RAG tool-retrieval index; other clients ignore
    # them. Falls back to the normal description if a tool has no RAG metadata.
    out = []
    for name, (_b, normal, schema, _t) in HACKTOOLS.items():
        short, long, examples = _META.get(name, (normal, normal, []))
        out.append({
            "name": name,
            "description": normal,
            "shortDescription": short,
            "longDescription": long,
            "exampleQueries": examples,
            "inputSchema": schema,
        })
    return out


def _call_tool(name, arguments):
    entry = HACKTOOLS.get(name)
    if entry is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    builder, _desc, _schema, timeout = entry
    try:
        built = builder(arguments or {})
    except ValueError as exc:                          # bad arguments
        return {"content": [{"type": "text", "text": f"invalid arguments: {exc}"}],
                "isError": True}
    except Exception as exc:                            # noqa: BLE001
        return {"content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True}
    if len(built) == 3:                                # builder may override timeout
        argv, binary, timeout = built
    else:
        argv, binary = built
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
    missing = [n for n in HACKTOOLS if n not in _META]
    print(f"[rag metadata] {'ok — every tool has short/long/examples' if not missing else 'MISSING: ' + ', '.join(missing)}")
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
