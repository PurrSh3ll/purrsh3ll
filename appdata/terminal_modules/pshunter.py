#!/usr/bin/env python3
"""pshunter — guided offensive workflow runner (skeleton).

A phase-driven companion for pentest / CTF work: it walks a target through the
classic kill-chain stages — host discovery, port enumeration, service detection,
vulnerability scanning, CVE lookup and service exploitation — one deliberate step
at a time. Every phase records what it found so the operator can review progress
via [s] status and browse results via [d] database.

This file is an early skeleton: it draws the banner, lays out the menu and routes
the user's choice to placeholder handlers. The real engines (nmap wrappers, the
SQLite store and the qtermwidget shell-spawning) are intentionally not wired yet.

Authorised use only. Run pshunter exclusively against assets you own or are
explicitly permitted to test.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime


# ── terminal colours ──────────────────────────────────────────────────────────
# Auto-disabled when output is not a TTY or NO_COLOR is set, so piping stays clean.
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str) -> str:
    return code if _COLOR else ""


RESET   = _c("\033[0m")
BOLD    = _c("\033[1m")
DIM     = _c("\033[2m")
CYAN    = _c("\033[36m")
GREEN   = _c("\033[32m")
RED     = _c("\033[31m")
YELLOW  = _c("\033[33m")
MAGENTA = _c("\033[35m")
BROWN   = _c("\033[38;2;205;133;63m")   # 24-bit brown (peru) for the options hint line


APP_NAME    = "pshunter"
APP_TAGLINE = "modular offensive security toolkit"
APP_VERSION = "1.0"


# ── banner ────────────────────────────────────────────────────────────────────
def _fallback_banner() -> str:
    """Hand-drawn banner used when pyfiglet is unavailable."""
    return r"""
           _                 _
 _ __  ___| |__  _   _ _ __ | |_ ___ _ __
| '_ \/ __| '_ \| | | | '_ \| __/ _ \ '__|
| |_) \__ \ | | | |_| | | | | ||  __/ |
| .__/|___/_| |_|\__,_|_| |_|\__\___|_|
|_|
"""


def render_banner() -> str:
    """ASCII-art app name. Prefers pyfiglet (ansi_shadow), falls back to a static
    banner so the tool still runs without the dependency."""
    try:
        from pyfiglet import Figlet
        return Figlet(font="ansi_shadow", width=200).renderText(APP_NAME).rstrip("\n")
    except Exception:
        return _fallback_banner().rstrip("\n")


def print_header() -> None:
    print(CYAN + BOLD + render_banner() + RESET)
    print()
    print(f"{DIM}  {APP_TAGLINE} · v{APP_VERSION}{RESET}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{YELLOW}  ⚠ unprivileged — running as a normal user{RESET}"
              f"{DIM} — press {RESET}{YELLOW}[u]{RESET}{DIM} upgrade{RESET}")
    else:
        print(f"{GREEN}  ● root — full scan capability (raw sockets){RESET}")
    print()


# ── phases (the offensive kill-chain, in order) ───────────────────────────────
# Each entry: (menu key, name, one-line intent). The order is the recommended
# progression; nothing forces it, but later phases build on earlier findings.
PHASES = [
    ("0", "Host discovery",       "find which hosts are alive on the target scope"),
    ("1", "Port enumeration",     "map open TCP/UDP ports on a live host"),
    ("2", "Service detection",    "fingerprint the service/version behind each port"),
    ("3", "Vuln scan",            "run vulnerability checks against detected services"),
    ("4", "CVE lookup",           "match service CPEs to known CVEs"),
    ("5", "Service exploitation", "attempt exploitation / access on a chosen service"),
    ("6", "Privilege Escalation", "escalate to root / SYSTEM on a compromised host"),
    ("7", "Persistence",          "maintain access on a compromised host"),
    ("8", "Covering Tracks",      "clean up artifacts after an authorised engagement"),
]
_PHASES = {key: (name, desc) for key, name, desc in PHASES}


# ── scan-time budget ──────────────────────────────────────────────────────────
MIN_MINUTES = 1        # floor
MAX_MINUTES = 1440     # ceiling: 24 h
DEFAULT_MINUTES = 10   # Enter accepts this


# ── navigation words (accepted at any sub-prompt) ─────────────────────────────
_BACK_WORDS = {"b", "back"}
_HELP_WORDS = {"h", "help", "?"}
_MENU_WORDS = {"m", "menu"}          # jump straight back to the main menu (any depth)


# ── menu ──────────────────────────────────────────────────────────────────────
def print_menu() -> None:
    print(f"  {DIM}workflow{RESET}")
    for key, name, desc in PHASES:
        print(f"  {CYAN}[{key}]{RESET} {BOLD}{name}{RESET}")
    print()
    print(f"  {DIM}actions{RESET}")
    print(f"  {CYAN}[s]{RESET} {BOLD}status{RESET}")
    print(f"  {CYAN}[d]{RESET} {BOLD}database{RESET}")
    print(f"  {CYAN}[n]{RESET} {BOLD}new session{RESET}")
    if not _is_root():
        print(f"  {CYAN}[u]{RESET} {BOLD}upgrade{RESET}")
    print(f"  {CYAN}[h]{RESET} {BOLD}help{RESET}")
    print()
    print(f"  {DIM}/exit  quit{RESET}")


# ── help ──────────────────────────────────────────────────────────────────────
def print_help() -> None:
    """Full usage — kept off the main screen so it stays clean."""
    print(f"\n{BOLD}{CYAN}pshunter — help{RESET}\n")

    print(f"{BOLD}Phases{RESET}")
    for key, name, desc in PHASES:
        print(f"  {CYAN}[{key}]{RESET} {BOLD}{name:<20}{RESET}{DIM} {desc}{RESET}")
    print()

    print(f"{BOLD}Host discovery — target formats{RESET}")
    print(f"  {DIM}192.168.1.0/24{RESET}             subnet in CIDR notation")
    print(f"  {DIM}192.168.1.0{RESET}                bare IP — assumed /24")
    print(f"  {DIM}192.168.1.10-192.168.1.40{RESET}  range, full end address")
    print(f"  {DIM}192.168.1.10-40{RESET}            range, end = last octet")
    print()

    print(f"{BOLD}Time budget{RESET}")
    print(f"  {DIM}minutes · Enter = {DEFAULT_MINUTES} · {MIN_MINUTES}–{MAX_MINUTES} (24 h){RESET}")
    print()

    print(f"{BOLD}Menu actions{RESET}")
    print(f"  {BOLD}status{RESET}     command history + state; {BOLD}v <n>{RESET} view command+output "
          f"in a new terminal, {BOLD}stop <n>{RESET} abort, {BOLD}c{RESET} clear finished")
    print(f"  {BOLD}database{RESET}   discovered hosts; type a number for its ports, "
          f"{BOLD}r <n>{RESET} remove, {BOLD}c{RESET} wipe all")
    print(f"  {DIM}           inside a host: {BOLD}[f]{RESET}{DIM} findings, {BOLD}[p]{RESET}{DIM} progress "
          f"(per-phase tracker — which phases ran and what's pending; a number runs one){RESET}")
    print(f"  {BOLD}new session{RESET}  wipe the whole database (hosts + history) for a fresh start")
    print(f"  {BOLD}upgrade{RESET}      re-run under sudo for root (SYN/UDP scans); progress is kept")
    print()

    print(f"{BOLD}Navigation{RESET}")
    print(f"  {BOLD}h{RESET} / {BOLD}help{RESET} / {BOLD}?{RESET}   show this screen")
    print(f"  {BOLD}b{RESET} / {BOLD}back{RESET}       return to the menu")
    print(f"  {BOLD}/exit{RESET}          quit pshunter")
    print()


# ── input helper ──────────────────────────────────────────────────────────────
class _ExitApp(Exception):
    """Raised from any prompt when the user types /exit — quits the whole app."""


class _ToMenu(Exception):
    """Raised from any prompt when the user types m/menu — pops out of every nested view
    straight back to the main menu (the main loop catches it and just redraws the menu)."""


def _ask(label: str) -> "str | None":
    """Prompt for a line. Returns the stripped text, or None if the user aborts
    (Ctrl+C / EOF) — callers treat None as 'back to the menu'. Typing /exit anywhere
    raises _ExitApp (quit); m/menu raises _ToMenu (jump to the main menu)."""
    try:
        value = input(f"{BOLD}{label}{RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    low = value.lower()
    if low in ("/exit", "\\exit"):
        raise _ExitApp
    if low in _MENU_WORDS:
        raise _ToMenu
    return value


def _ctx_ask(module: str, options: str = "") -> "str | None":
    """Prompt tagged with the module you're in (coloured, for readability) and, one
    line above, a short hint of what you can type — tinted brown so it reads as
    interactive options, distinct from normal output."""
    if options:
        print(f"  {BROWN}{options}{RESET}")
    return _ask(f"{CYAN}[{module}]{RESET}{DIM} ›{RESET}")


def _hr() -> None:
    """Thin divider used inside interactive views to separate one chosen action's
    output from the next."""
    print(f"{DIM}{'─' * 56}{RESET}")


# ── host discovery (phase 1) ──────────────────────────────────────────────────
# A range wider than this is refused for expansion — use CIDR instead (nmap can
# only express an arbitrary start-end as a single token when the hosts share the
# same /24; otherwise we would have to hand nmap a huge explicit target list).
_MAX_RANGE_EXPAND = 8192


def parse_discovery_target(value: str) -> "tuple[bool, str, dict]":
    """Validate a host-discovery scope. Accepts a CIDR subnet, a bare IP (taken as
    /24), or an inclusive range ``start-end`` where ``end`` is either a full IPv4
    address or just the final octet. Returns ``(ok, error, parsed)`` where, on
    success, ``parsed = {"scope": <str>, "hosts": <int>, "targets": [<nmap arg>…]}``.
    """
    value = value.strip()
    if not value:
        return False, "empty — give a subnet or range", {}

    if "-" in value:                                   # start-end range (IPv4)
        left, _, right = value.partition("-")
        try:
            start = ipaddress.ip_address(left.strip())
        except ValueError:
            return False, "range start is not a valid IPv4 address", {}
        if start.version != 4:
            return False, "ranges are IPv4 only", {}
        right = right.strip()
        if "." in right:
            try:
                end = ipaddress.ip_address(right)
            except ValueError:
                return False, "range end is not a valid IPv4 address", {}
        elif right.isdigit() and 0 <= int(right) <= 255:
            end = ipaddress.ip_address((int(start) & 0xFFFFFF00) | int(right))
        else:
            return False, "range end must be an IP or a 0-255 octet", {}
        if int(end) < int(start):
            return False, "range end is before its start", {}
        hosts = int(end) - int(start) + 1
        if int(start) >> 8 == int(end) >> 8:           # same /24 -> compact nmap token
            targets = [f"{str(start).rsplit('.', 1)[0]}.{int(start) & 0xFF}-{int(end) & 0xFF}"]
        elif hosts <= _MAX_RANGE_EXPAND:               # spans /24s -> explicit list
            targets = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        else:
            return False, "range too large — use CIDR notation", {}
        return True, "", {"scope": f"{start}-{end}", "hosts": hosts, "targets": targets}

    if "/" not in value:                               # bare IP -> assume a mask
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False, "not a valid IP address", {}
        value = f"{value}/{24 if addr.version == 4 else 64}"

    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False, "not a valid subnet (CIDR)", {}
    return True, "", {"scope": str(net), "hosts": net.num_addresses, "targets": [str(net)]}


def _prompt_minutes(module: str, title: str, detail: str) -> "int | None":
    """Show a one-line summary (title + detail + default time) and read the time
    budget. Enter accepts the default; a number is validated to 1–1440."""
    print(f"\n{GREEN}✓{RESET} {BOLD}{title}{RESET} · {detail} · {DIM}⏱ {DEFAULT_MINUTES}m{RESET}")
    while True:
        v = _ctx_ask(module, f"<minutes {MIN_MINUTES}-{MAX_MINUTES}, Enter={DEFAULT_MINUTES}> · [h] help · [b] back · [m] menu")
        if v is None or v.lower() in _BACK_WORDS:
            return None
        if v.lower() in _HELP_WORDS:
            print_help()
            continue
        if v == "":
            return DEFAULT_MINUTES
        if v.isdigit() and MIN_MINUTES <= int(v) <= MAX_MINUTES:
            return int(v)
        print(f"{RED}✗ 1–{MAX_MINUTES} minutes{RESET}")


def _handle_host_discovery() -> None:
    """Phase 1 flow: read + validate the scope, then the time, then launch."""
    while True:
        value = _ctx_ask("discovery", "<subnet / range> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        ok, err, parsed = parse_discovery_target(value)
        if not ok:
            print(f"{RED}✗ {err}{RESET}")
            continue
        minutes = _prompt_minutes("discovery", "Host discovery",
                                  f"{parsed['scope']} · {parsed['hosts']} host(s)")
        if minutes is None:
            return
        _start_discovery(parsed, minutes)
        print(f"\n{GREEN}▶ host discovery running in the background{RESET} "
              f"{DIM}({parsed['scope']}, ⏱ {minutes}m) — check {BOLD}[s] status{RESET}")
        return


def _handle_port_enum() -> None:
    """Phase 2 flow: read + validate a single target IP, then the time, then launch
    the concurrent port scans."""
    while True:
        value = _ctx_ask("ports", "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        minutes = _prompt_minutes("ports", "Port enumeration", ip)
        if minutes is None:
            return
        _start_port_enum(ip, minutes)
        print(f"\n{GREEN}▶ port enumeration running in the background{RESET} "
              f"{DIM}({ip} · fast + full TCP + UDP, ⏱ {minutes}m) — check {BOLD}[s] status{RESET}")
        return


def _handle_service_detection() -> None:
    """Phase 3 flow: read a target IP, then the time, then launch -sV -sC (+ OS) on the
    open ports discovered in phase 2."""
    while True:
        value = _ctx_ask("service", "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        if not fetch_ports(ip):
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[1] Port "
                  f"enumeration{RESET}{DIM} first (OS scan still runs if root){RESET}")
        minutes = _prompt_minutes("service", "Service detection", ip)
        if minutes is None:
            return
        _start_service_detection(ip, minutes)
        print(f"\n{GREEN}▶ service detection running in the background{RESET} "
              f"{DIM}({ip} · -sV -sC + OS, ⏱ {minutes}m) — check {BOLD}[s] status{RESET}")
        return


def _handle_vuln_scan() -> None:
    """Phase 4 flow: read a target IP, then the time, then launch targeted vuln/auth
    NSE scans mapped to the host's detected services."""
    while True:
        value = _ctx_ask("vuln", "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        if not fetch_ports(ip):
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[1] Port "
                  f"enumeration{RESET}{DIM} (and {BOLD}[2] Service detection{RESET}{DIM}) first{RESET}")
            continue
        print(f"{DIM}vuln + auth scripting{RESET}")
        minutes = _prompt_minutes("vuln", "Vuln scan", ip)
        if minutes is None:
            return
        _start_vuln_scan(ip, minutes)
        print(f"\n{GREEN}▶ vuln scan running in the background{RESET} "
              f"{DIM}({ip} · targeted NSE vuln+auth, ⏱ {minutes}m) — check {BOLD}[s] status{RESET}")
        return


# ── host-discovery nmap engine ────────────────────────────────────────────────
# Two passes, per OSCP/HTB practice. Pass 1 is a fast default sweep: as root, -sn
# already fires ICMP echo + TCP SYN 443 + TCP ACK 80 + ICMP timestamp, and ARP on
# a local segment — this catches the easy, responsive hosts quickly. Pass 2 is a
# thorough multi-probe sweep for hosts that drop the common probes: extra ICMP
# types plus TCP SYN/ACK and UDP probes across the ports firewalls usually let
# through (web/DNS/SMB/RDP/SNMP). Sent in parallel so at least one gets through.
# Both use -n (no DNS) for speed; results from the two passes are unioned.
_DISCOVERY_FAST = ["-sn", "-n", "-T4", "--max-retries", "1"]
_DISCOVERY_SLOW = [
    "-sn", "-n", "-T3",
    "-PE", "-PP", "-PM",                                     # ICMP echo / timestamp / netmask
    "-PS21,22,23,25,53,80,110,139,443,445,3389,8080",       # TCP SYN to common open ports
    "-PA80,443,3389",                                        # TCP ACK (bypass stateless SYN blocks)
    "-PU53,161,137",                                         # UDP to DNS / SNMP / NetBIOS
]


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _host_from_elem(elem) -> "dict | None":
    """Build an up-host dict from one nmap ``<host>`` XML element (no ports: -sn)."""
    st = elem.find("status")
    if st is None or st.get("state") != "up":
        return None
    ip = mac = vendor = hostname = None
    for addr in elem.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4":
            ip = addr.get("addr")
        elif kind == "mac":
            mac, vendor = addr.get("addr"), addr.get("vendor")
    if not ip:
        return None
    hn = elem.find("hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name")
    return {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname}


def _host_ports_from_elem(elem) -> "dict | None":
    """Extract open (or open|filtered) ports from one nmap ``<host>`` element. Each
    port keeps its state and, when present, nmap's service guess (name/product/
    version) — filled in properly later by the service-detection phase."""
    ip = None
    for addr in elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr")
    if not ip:
        return None
    rows = []
    for port in elem.findall("ports/port"):
        pstate = port.find("state")
        state = pstate.get("state") if pstate is not None else None
        if state not in ("open", "open|filtered"):
            continue
        svc = port.find("service")
        service = None
        if svc is not None:
            service = {"name": svc.get("name"), "product": svc.get("product"),
                       "version": svc.get("version")}
        rows.append({"port": int(port.get("portid")), "proto": port.get("protocol") or "tcp",
                     "state": state, "service": service})
    return {"ip": ip, "ports": rows} if rows else None


def _host_detail_from_elem(elem) -> "dict | None":
    """Extract service-detection results from one nmap ``<host>`` element: probed
    services (name/product/version/cpe), NSE (-sC) script output per port (plus any
    host-level scripts under port 0), and the best OS match."""
    ip = None
    for addr in elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr")
    if not ip:
        return None
    services, scripts, hostnames = [], [], []
    for port in elem.findall("ports/port"):
        portid = int(port.get("portid"))
        proto = port.get("protocol") or "tcp"
        svc = port.find("service")
        if svc is not None and svc.get("method") == "probed":
            cpe = None
            for c in svc.findall("cpe"):
                txt = (c.text or "").strip()
                if txt and (cpe is None or txt.startswith("cpe:/a")):
                    cpe = txt                       # prefer the application CPE
            services.append({"port": portid, "proto": proto, "name": svc.get("name"),
                             "product": svc.get("product"), "version": svc.get("version"),
                             "cpe": cpe})
            if svc.get("hostname"):                 # nmap resolves a name (often the TLS cert CN)
                hostnames.append({"port": portid, "hostname": svc.get("hostname"), "source": "service"})
        for scr in port.findall("script"):
            scripts.append({"port": portid, "proto": proto,
                            "id": scr.get("id"), "output": scr.get("output")})
    for scr in elem.findall("hostscript/script"):   # host-level scripts (port 0)
        scripts.append({"port": 0, "proto": "", "id": scr.get("id"),
                        "output": scr.get("output")})
    om = elem.find("os/osmatch")
    os_name = om.get("name") if om is not None else None
    if not (services or scripts or os_name):
        return None
    return {"ip": ip, "services": services, "scripts": scripts, "os": os_name,
            "hostnames": hostnames}


def _run_nmap(args: list, targets: list, on_items, deadline: "float | None" = None,
              should_stop=None, parse_elem=None):
    """Run nmap (XML to a temp file), tail it with an incremental parser and hand each
    parsed ``<host>`` element to ``on_items`` as it appears. ``parse_elem`` turns an
    element into an item (defaults to the host parser for -sn; the port parser is used
    for port scans). XML feeds the parser; nmap's normal stdout is captured separately
    (for the report terminal). Returns ``(items, output_text)``, or ``(None, None)`` if
    nmap is missing. ``deadline`` hard-caps the run; ``should_stop`` is polled each tick
    to kill it early. Whatever streamed so far is kept."""
    parse_elem = parse_elem or _host_from_elem
    import xml.etree.ElementTree as ET
    tmp = tempfile.NamedTemporaryFile(prefix="pshunter_", suffix=".xml", delete=False)
    tmp.close()
    out = tempfile.NamedTemporaryFile(prefix="pshunter_out_", suffix=".txt", delete=False)
    full = ["nmap", "-oX", tmp.name] + args + targets
    try:
        proc = subprocess.Popen(full, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    except FileNotFoundError:
        out.close()
        _safe_unlink(tmp.name)
        _safe_unlink(out.name)
        return None, None
    out.close()

    parser = ET.XMLPullParser(("end",))
    all_items, pending, pos = [], [], 0
    start = time.time()

    def _flush():
        if pending:
            on_items(list(pending))
            all_items.extend(pending)
            pending.clear()

    def _consume():
        nonlocal pos
        try:
            with open(tmp.name, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read()
                pos = fh.tell()
        except OSError:
            chunk = b""
        if chunk:
            try:
                parser.feed(chunk)
            except ET.ParseError:
                pass
            for _ev, elem in parser.read_events():
                if elem.tag == "host":
                    item = parse_elem(elem)
                    if item:
                        pending.append(item)
                    elem.clear()
        return chunk

    try:
        while True:
            alive = proc.poll() is None
            chunk = _consume()
            if len(pending) >= 8:
                _flush()
            if not alive and not chunk:
                break
            timed_out = deadline is not None and (time.time() - start) > deadline
            if timed_out or (should_stop is not None and should_stop()):
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                _consume()
                break
            if alive:
                time.sleep(0.4)
        _flush()
    finally:
        _safe_unlink(tmp.name)
    try:
        with open(out.name, "r", encoding="utf-8", errors="replace") as fh:
            output = fh.read()
    except OSError:
        output = ""
    _safe_unlink(out.name)
    return all_items, output


# ── self-IP guard (never record loopback / the scanner's own address) ─────────
_OWN_ADDRS: "set | None" = None


def _own_addresses() -> set:
    """This machine's interface IPs, computed once and cached."""
    global _OWN_ADDRS
    if _OWN_ADDRS is None:
        addrs: set = set()
        try:
            out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True,
                                 text=True, timeout=10, stdin=subprocess.DEVNULL).stdout
            for line in out.splitlines():
                parts = line.split()
                for i, tok in enumerate(parts):
                    if tok in ("inet", "inet6") and i + 1 < len(parts):
                        addrs.add(parts[i + 1].split("/")[0])
        except (OSError, subprocess.SubprocessError):
            pass
        _OWN_ADDRS = addrs
    return _OWN_ADDRS


def _refresh_own_addresses() -> None:
    """Force the own-address cache to be recomputed (call at every scan start so a
    mid-session IP change — e.g. connecting a VPN — is reflected in the guard)."""
    global _OWN_ADDRS
    _OWN_ADDRS = None
    _own_addresses()


def _is_self_ip(ip: str) -> bool:
    """True for loopback or one of this machine's own interface addresses."""
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return True
    except ValueError:
        return False
    return ip in _own_addresses()


# ── database (discovered hosts) ───────────────────────────────────────────────
# This script lives in appdata/terminal_modules/; keep the runtime DB up in appdata/
# (a data location) rather than next to the code.
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pshunter.db")
# Offline CPE→CVE index (built by the installer from NVD; see build_cve_index). Read-only.
CVE_INDEX_PATH = os.path.join(os.path.dirname(DB_PATH), "cve_index.db")
# CISA Known Exploited Vulnerabilities — CVE ids actually exploited in the wild. Bundled
# text file (one CVE per line); used to surface KEV matches first in the findings view.
KEV_PATH = os.path.join(os.path.dirname(DB_PATH), "kev.txt")
_KEV_CACHE: "set | None" = None


def _load_kev() -> set:
    """The set of CISA KEV CVE ids (cached). Empty if the file is missing."""
    global _KEV_CACHE
    if _KEV_CACHE is None:
        kev = set()
        try:
            with open(KEV_PATH, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("CVE-"):
                        kev.add(line)
        except OSError:
            pass
        _KEV_CACHE = kev
    return _KEV_CACHE
_DB_LOCK = threading.Lock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    vendor      TEXT,
    hostname    TEXT,
    os          TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);
CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created     TEXT,
    phase       TEXT,
    name        TEXT,
    command     TEXT,
    state       TEXT,
    hosts       INTEGER,
    error       TEXT,
    output      TEXT,
    run         TEXT
);
CREATE TABLE IF NOT EXISTS ports (
    ip          TEXT,
    port        INTEGER,
    proto       TEXT,
    state       TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS services (
    ip          TEXT,
    port        INTEGER,
    proto       TEXT,
    name        TEXT,
    product     TEXT,
    version     TEXT,
    cpe         TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS scripts (
    ip          TEXT,
    port        INTEGER,
    proto       TEXT,
    script      TEXT,
    output      TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, port, proto, script)
);
CREATE TABLE IF NOT EXISTS vulns (
    ip          TEXT,
    port        INTEGER,
    proto       TEXT,
    script      TEXT,
    state       TEXT,
    cve         TEXT,
    risk        TEXT,
    summary     TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, port, proto, script)
);
CREATE TABLE IF NOT EXISTS exploit_steps (
    ip          TEXT,
    port        INTEGER,
    proto       TEXT,
    service     TEXT,
    step        INTEGER,
    status      TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, port, proto, service, step)
);
CREATE TABLE IF NOT EXISTS hostnames (
    ip          TEXT,
    port        INTEGER,
    hostname    TEXT,
    source      TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (ip, hostname)
);
"""


def _chown_db_to_user() -> None:
    """When running as root via sudo, hand the DB and its WAL sidecar files back to the
    invoking user (SUDO_UID/GID). Called on every connection so ownership is kept
    correct continuously — surviving a crash / SIGKILL / terminal close, unlike an
    exit-time fixup. No-op when not root or not launched through sudo."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return
    try:
        uid, gid = int(uid), int(os.environ.get("SUDO_GID") or uid)
    except ValueError:
        return
    for suffix in ("", "-wal", "-shm"):          # SQLite WAL keeps two sidecar files
        path = DB_PATH + suffix
        if os.path.exists(path):
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass


def _db_connect() -> "sqlite3.Connection":
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    # Migrate pre-existing tables that predate a column (IF NOT EXISTS above won't
    # alter an existing table).
    jcols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if jcols and "output" not in jcols:
        conn.execute("ALTER TABLE jobs ADD COLUMN output TEXT")
    if jcols and "run" not in jcols:
        conn.execute("ALTER TABLE jobs ADD COLUMN run TEXT")
    hcols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    if hcols and "os" not in hcols:
        conn.execute("ALTER TABLE hosts ADD COLUMN os TEXT")
    conn.commit()
    _chown_db_to_user()          # keep the DB user-owned even while running as root
    return conn


def save_hosts(hosts: list) -> int:
    """Upsert discovered hosts by IP; keeps first non-null mac/vendor/hostname/os."""
    if not hosts:
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    saved = 0
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for h in hosts:
                ip = h.get("ip")
                if not ip or _is_self_ip(ip):       # never store loopback / own address
                    continue
                conn.execute(
                    "INSERT INTO hosts (ip, mac, vendor, hostname, os, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET "
                    "  mac       = COALESCE(excluded.mac, mac), "
                    "  vendor    = COALESCE(excluded.vendor, vendor), "
                    "  hostname  = COALESCE(excluded.hostname, hostname), "
                    "  os        = COALESCE(excluded.os, os), "
                    "  last_seen = excluded.last_seen",
                    (ip, h.get("mac"), h.get("vendor"), h.get("hostname"), h.get("os"), now, now),
                )
                saved += 1
            conn.commit()
        finally:
            conn.close()
    return saved


def fetch_hosts() -> list:
    """(ip, mac, vendor, hostname, os, nports) rows, sorted by IP; nports is the count
    of open ports recorded for the host. [] if the DB is empty."""
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        rows = conn.execute(
            "SELECT h.ip, h.mac, h.vendor, h.hostname, h.os, "
            "  (SELECT COUNT(*) FROM ports p WHERE p.ip = h.ip) "
            "FROM hosts h").fetchall()
    except sqlite3.OperationalError:      # file exists but schema not created yet
        return []
    finally:
        conn.close()

    def _key(row):
        try:
            return (0, int(ipaddress.ip_address(row[0])))
        except ValueError:
            return (1, 0)
    rows.sort(key=_key)
    return rows


def save_ports(ip: str, rows: list) -> int:
    """Upsert open ports for a host by (ip, port, proto). When a scan carried a service
    guess (nmap's port->name table, or -sV later), it's upserted into the services
    table too — kept non-null so the service-detection phase only enriches it."""
    if not ip or not rows or _is_self_ip(ip):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for r in rows:
                conn.execute(
                    "INSERT INTO ports (ip, port, proto, state, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                    "  state = excluded.state, last_seen = excluded.last_seen",
                    (ip, r["port"], r["proto"], r.get("state"), now, now),
                )
                svc = r.get("service") or {}
                if svc.get("name") or svc.get("product") or svc.get("version"):
                    conn.execute(
                        "INSERT INTO services (ip, port, proto, name, product, version, cpe, "
                        "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                        "  name     = COALESCE(excluded.name, name), "
                        "  product  = COALESCE(excluded.product, product), "
                        "  version  = COALESCE(excluded.version, version), "
                        "  last_seen = excluded.last_seen",
                        (ip, r["port"], r["proto"], svc.get("name"), svc.get("product"),
                         svc.get("version"), None, now, now),
                    )
            conn.commit()
        finally:
            conn.close()
    return len(rows)


def _fetch(query: str, params: tuple) -> list:
    """Run a read query, returning [] if the DB/table isn't there yet."""
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        return conn.execute(query, params).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def fetch_ports(ip: str) -> list:
    """(port, proto, state) rows for a host, TCP first then UDP, ascending port."""
    rows = _fetch("SELECT port, proto, state FROM ports WHERE ip = ?", (ip,))
    return sorted(rows, key=lambda r: (r[1], r[0]))


def fetch_services(ip: str) -> dict:
    """{(port, proto): (name, product, version, cpe)} for a host."""
    rows = _fetch("SELECT port, proto, name, product, version, cpe FROM services WHERE ip = ?", (ip,))
    return {(p, pr): (n, prod, ver, cpe) for p, pr, n, prod, ver, cpe in rows}


def save_services(ip: str, rows: list) -> int:
    """Upsert probed service data (-sV) by (ip, port, proto), overwriting the earlier
    port-enum guess with the real name/product/version/cpe."""
    if not ip or not rows or _is_self_ip(ip):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for r in rows:
                conn.execute(
                    "INSERT INTO services (ip, port, proto, name, product, version, cpe, "
                    "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                    "  name     = COALESCE(excluded.name, name), "
                    "  product  = COALESCE(excluded.product, product), "
                    "  version  = COALESCE(excluded.version, version), "
                    "  cpe      = COALESCE(excluded.cpe, cpe), "
                    "  last_seen = excluded.last_seen",
                    (ip, r["port"], r["proto"], r.get("name"), r.get("product"),
                     r.get("version"), r.get("cpe"), now, now),
                )
            conn.commit()
        finally:
            conn.close()
    return len(rows)


def save_scripts(ip: str, rows: list) -> int:
    """Upsert NSE script output by (ip, port, proto, script) — port 0 = host-level —
    and, in the same transaction, extract any finding from each script into the vulns
    table (so both -sC and vuln-scan output feed the findings summary, no re-scan)."""
    if not ip or not rows or _is_self_ip(ip):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for r in rows:
                sid = r.get("id")
                if not sid:
                    continue
                port, proto, output = int(r.get("port") or 0), r.get("proto") or "", r.get("output")
                conn.execute(
                    "INSERT INTO scripts (ip, port, proto, script, output, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto, script) DO UPDATE SET "
                    "  output = excluded.output, last_seen = excluded.last_seen",
                    (ip, port, proto, sid, output, now, now),
                )
                f = _extract_finding(sid, output or "")
                if f:
                    conn.execute(
                        "INSERT INTO vulns (ip, port, proto, script, state, cve, risk, summary, "
                        "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(ip, port, proto, script) DO UPDATE SET "
                        "  state = excluded.state, cve = excluded.cve, risk = excluded.risk, "
                        "  summary = excluded.summary, last_seen = excluded.last_seen",
                        (ip, port, proto, sid, f["state"], f["cve"], f["risk"], f["summary"], now, now),
                    )
                for hn in _extract_hostnames(ip, sid, output or ""):     # cert SANs, redirects, SMB FQDN
                    conn.execute(
                        "INSERT INTO hostnames (ip, port, hostname, source, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip, hostname) DO UPDATE SET "
                        "  last_seen = excluded.last_seen",
                        (ip, port, hn, sid, now, now),
                    )
            conn.commit()
        finally:
            conn.close()
    return len(rows)


# a plausible DNS hostname (has a dot, valid label chars, not a bare IP)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def _valid_hostname(name: str, ip: str) -> "str | None":
    """Normalise & validate a candidate hostname; None if it isn't a usable DNS name."""
    n = (name or "").strip().lower().rstrip(".")
    if n.startswith("*."):                       # wildcard cert → keep the base domain
        n = n[2:]
    if not n or n == ip:
        return None
    if _HOSTNAME_RE.match(n) and not n.replace(".", "").isdigit():
        return n
    return None


def _extract_hostnames(ip: str, sid: str, output: str) -> set:
    """Pull DNS names out of one NSE script's output — TLS cert CN/SAN (ssl-cert), HTTP
    redirect targets (http-title/http-*), and SMB FQDN/domain (smb-os-discovery). These
    domains/vhosts are gold for phase 5 (add to /etc/hosts, vhost-fuzz)."""
    if not output:
        return set()
    cands = []
    if "ssl-cert" in sid or "ssl-" in sid:
        cands += re.findall(r"DNS:([A-Za-z0-9_.*-]+)", output)
        cands += re.findall(r"commonName=([A-Za-z0-9_.*-]+)", output)
    if sid.startswith("http-"):
        cands += re.findall(r"redirect to https?://([A-Za-z0-9_.-]+)", output, re.I)
        cands += re.findall(r"[Ll]ocation:\s*https?://([A-Za-z0-9_.-]+)", output)
    if sid == "smb-os-discovery":
        for pat in (r"FQDN:\s*(\S+)", r"Domain name:\s*(\S+)", r"DNS_?[Dd]omain[_ ]?[Nn]ame:\s*(\S+)",
                    r"Forest name:\s*(\S+)"):
            cands += re.findall(pat, output)
    return {h for h in (_valid_hostname(c, ip) for c in cands) if h}


def save_hostnames(ip: str, entries: list) -> None:
    """Store validated DNS names for a host (dedup by (ip, hostname)). ``entries`` is a
    list of {'port', 'hostname', 'source'} — e.g. nmap's per-service resolved name."""
    if not ip or not entries or _is_self_ip(ip):
        return
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for e in entries:
                hn = _valid_hostname(e.get("hostname"), ip)
                if not hn:
                    continue
                conn.execute(
                    "INSERT INTO hostnames (ip, port, hostname, source, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip, hostname) DO UPDATE SET "
                    "  last_seen = excluded.last_seen",
                    (ip, int(e.get("port") or 0), hn, e.get("source") or "service", now, now))
            conn.commit()
        finally:
            conn.close()


def fetch_hostnames(ip: str) -> list:
    """(hostname, port, source) DNS names discovered for a host, for phase-5 vhost work."""
    rows = _fetch("SELECT hostname, port, source FROM hostnames WHERE ip = ? ORDER BY hostname", (ip,))
    return rows


def save_os(ip: str, os_name: str) -> None:
    """Store the detected OS on the host row (overwrites a previous guess)."""
    if not ip or not os_name or _is_self_ip(ip):
        return
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            conn.execute(
                "INSERT INTO hosts (ip, os, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET os = excluded.os, last_seen = excluded.last_seen",
                (ip, os_name, now, now))
            conn.commit()
        finally:
            conn.close()


def fetch_host_os(ip: str) -> "str | None":
    rows = _fetch("SELECT os FROM hosts WHERE ip = ?", (ip,))
    return rows[0][0] if rows and rows[0][0] else None


def fetch_scripts(ip: str, port: int, proto: str) -> list:
    """(script, output) rows for one port (proto '' + port 0 = host-level scripts)."""
    return _fetch("SELECT script, output FROM scripts WHERE ip = ? AND port = ? AND proto = ?",
                  (ip, port, proto))


def fetch_scripted_ports(ip: str) -> set:
    """{(port, proto)} that carry per-port NSE script output — i.e. the ports where
    there's more to see (from service detection / vuln scan)."""
    rows = _fetch("SELECT DISTINCT port, proto FROM scripts WHERE ip = ? AND port != 0", (ip,))
    return {(p, pr) for p, pr in rows}


def fetch_vulns(ip: str) -> list:
    """(port, proto, script, state, cve, risk, summary) findings for a host."""
    rows = _fetch("SELECT port, proto, script, state, cve, risk, summary FROM vulns WHERE ip = ?", (ip,))
    return sorted(rows, key=lambda r: (r[0], r[2]))


def fetch_step_status(ip: str, port: int, proto: str, service: str) -> dict:
    """{step_index: status} for one service's checklist on a host ('done' / 'skip')."""
    rows = _fetch("SELECT step, status FROM exploit_steps WHERE ip = ? AND port = ? "
                  "AND proto = ? AND service = ?", (ip, port, proto, service))
    return {step: status for step, status in rows}


def set_step_status(ip: str, port: int, proto: str, service: str, step: int,
                    status: "str | None") -> None:
    """Persist one checklist step's status; status None clears it back to 'to-do'."""
    if not ip or _is_self_ip(ip):
        return
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            if status is None:
                conn.execute("DELETE FROM exploit_steps WHERE ip = ? AND port = ? AND "
                             "proto = ? AND service = ? AND step = ?",
                             (ip, port, proto, service, step))
            else:
                conn.execute(
                    "INSERT INTO exploit_steps (ip, port, proto, service, step, status, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto, service, step) DO UPDATE SET "
                    "  status = excluded.status, last_seen = excluded.last_seen",
                    (ip, port, proto, service, step, status, now))
            conn.commit()
        finally:
            conn.close()


# ── background jobs (feed [s] status) ─────────────────────────────────────────
_JOBS: list = []
_JOBS_LOCK = threading.Lock()


# ── job persistence (status history survives across app restarts) ─────────────
def _job_insert(job: dict) -> None:
    """Insert a new job row and stash its rowid on the job for later updates."""
    with _DB_LOCK:
        conn = _db_connect()
        try:
            cur = conn.execute(
                "INSERT INTO jobs (created, phase, name, command, state, hosts, error, output, run) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (job["created"], job["phase"], job["name"], job["command"],
                 job["state"], job["hosts"], job["error"], job["output"], job.get("run")))
            job["db_id"] = cur.lastrowid
            conn.commit()
        finally:
            conn.close()


def _job_update(job: dict) -> None:
    """Persist the job's current state / host count / error / captured output."""
    if job.get("db_id") is None:
        return
    with _DB_LOCK:
        conn = _db_connect()
        try:
            conn.execute(
                "UPDATE jobs SET state = ?, hosts = ?, error = ?, output = ? WHERE id = ?",
                (job["state"], job["hosts"], job["error"], job["output"], job["db_id"]))
            conn.commit()
        finally:
            conn.close()


def _load_jobs() -> None:
    """Reload the saved command history into _JOBS at startup. A job left 'running'
    from a previous session is no longer alive, so it is loaded (and persisted) as
    'aborted'."""
    if not os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        rows = conn.execute("SELECT id, created, phase, name, command, state, hosts, "
                            "error, output, run FROM jobs ORDER BY id").fetchall()
    except sqlite3.OperationalError:      # jobs table not created yet
        return
    finally:
        conn.close()
    corrected = []
    with _JOBS_LOCK:
        _JOBS.clear()
        for jid, created, phase, name, command, state, hosts, error, output, run in rows:
            st = "aborted" if state == "running" else state
            job = {"db_id": jid, "created": created, "phase": phase, "name": name,
                   "command": command, "state": st, "hosts": hosts or 0,
                   "found": set(), "error": error, "output": output,
                   "run": run or f"job{jid}",    # pre-run-column jobs group as singletons
                   "cancel": threading.Event()}
            _JOBS.append(job)
            if st != state:
                corrected.append(job)
    for job in corrected:                 # write back the running->aborted fix
        _job_update(job)


def _next_run_id() -> str:
    """A unique id for one phase execution (the batch of commands launched together).
    Time-based so it never collides with a run id reloaded from a previous session."""
    return str(time.time_ns())


def _new_job(phase: str, name: str, command: str, run: "str | None" = None) -> dict:
    # each phase execution shares one run id so status can group its commands; a job with
    # no explicit run (single-command phases) gets its own, i.e. its own status entry.
    job = {
        "phase": phase, "name": name, "command": command, "run": run or _next_run_id(),
        "state": "running", "hosts": 0, "found": set(), "error": None, "output": None,
        "cancel": threading.Event(),
        "created": datetime.now().isoformat(timespec="seconds"), "db_id": None,
    }
    _job_insert(job)                      # assigns job["db_id"]
    with _JOBS_LOCK:
        _JOBS.append(job)
    return job


def _run_pass(job: dict, args: list, targets: list, deadline: float) -> None:
    """Run one nmap pass, streaming live hosts to the DB and the job's found set.
    Honours job['cancel'] so status can abort a running scan. The job's state, host
    count and captured console output are persisted (output feeds the report view)."""
    def _on_hosts(batch):
        live = [h for h in batch if not _is_self_ip(h["ip"])]
        if live:
            save_hosts(live)
            job["found"].update(h["ip"] for h in live)
            job["hosts"] = len(job["found"])
            _job_update(job)
    try:
        hosts, output = _run_nmap(args, targets, _on_hosts, deadline=deadline,
                                  should_stop=job["cancel"].is_set)
        job["output"] = output
        if hosts is None:
            job["state"], job["error"] = "error", "nmap not found"
        elif job["cancel"].is_set():
            job["state"] = "aborted"
        else:
            job["state"] = "done"
    except Exception as exc:
        job["state"], job["error"] = "error", str(exc)
    finally:
        _job_update(job)


def _run_discovery(parsed: dict, minutes: int) -> None:
    """Fast and thorough passes run concurrently; their results are unioned into the
    DB. The whole phase shares one time budget — each pass is hard-capped at the full
    budget (not a split), so both may use all the minutes the user allowed."""
    _refresh_own_addresses()          # pick up any IP change since the last scan
    targets = parsed["targets"]
    deadline = max(1, minutes * 60)
    name = _PHASES["0"][0]
    run = _next_run_id()
    threads = []
    for args in (_DISCOVERY_FAST, _DISCOVERY_SLOW):
        command = " ".join(["nmap"] + args + targets)
        job = _new_job("0", name, command, run)
        t = threading.Thread(target=_run_pass, args=(job, args, targets, deadline), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _start_discovery(parsed: dict, minutes: int) -> None:
    """Launch discovery (both passes) in the background; the menu stays free."""
    threading.Thread(target=_run_discovery, args=(parsed, minutes), daemon=True).start()


# ── port enumeration (phase 2) ────────────────────────────────────────────────
# Runs several nmap port scans concurrently on one host, streaming open ports to the
# DB. A fast top-1000 (T4) gives an immediate working set; the full 65535-port TCP
# sweep is split into two halves at T3 (reliability over speed — completeness matters
# and T4 can miss ports on rate-limited/laggy targets); a top-100 UDP scan (root only)
# covers the common UDP services. -sV/-sC are deliberately left to the service phase.
def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _port_scan_specs() -> list:
    """(label, nmap-args) for the concurrent port scans. SYN scan needs root; fall
    back to a TCP connect scan otherwise. UDP is added only when root."""
    tcp = "-sS" if _is_root() else "-sT"
    specs = [
        ("fast",    [tcp, "-Pn", "-n", "--open", "-T4", "--top-ports", "1000"]),
        ("full-lo", [tcp, "-Pn", "-n", "--open", "-T3", "-p", "1-32767"]),
        ("full-hi", [tcp, "-Pn", "-n", "--open", "-T3", "-p", "32768-65535"]),
    ]
    if _is_root():
        specs.append(("udp", ["-sU", "-Pn", "-n", "--open", "-T4", "--top-ports", "100"]))
    return specs


def _run_port_pass(job: dict, args: list, ip: str, deadline: float) -> None:
    """Run one port scan on ``ip``, streaming open ports (and any service guess) to the
    DB. Honours job['cancel']; persists state, port count and captured output."""
    found = set()

    def _on_items(batch):
        for h in batch:
            rows = h.get("ports")
            if rows and not _is_self_ip(h["ip"]):
                save_ports(h["ip"], rows)
                found.update((r["port"], r["proto"]) for r in rows)
                job["hosts"] = len(found)
                _job_update(job)

    try:
        items, output = _run_nmap(args, [ip], _on_items, deadline=deadline,
                                  should_stop=job["cancel"].is_set,
                                  parse_elem=_host_ports_from_elem)
        job["output"] = output
        if items is None:
            job["state"], job["error"] = "error", "nmap not found"
        elif job["cancel"].is_set():
            job["state"] = "aborted"
        else:
            job["state"] = "done"
    except Exception as exc:
        job["state"], job["error"] = "error", str(exc)
    finally:
        _job_update(job)


def _run_port_enum(ip: str, minutes: int) -> None:
    """Concurrent port scans on one host, sharing one time budget (each capped at the
    full budget). The fast scan lands ports early while the full/UDP scans finish."""
    _refresh_own_addresses()
    save_hosts([{"ip": ip}])          # make sure the target shows in the hosts list
    deadline = max(1, minutes * 60)
    name = _PHASES["1"][0]
    run = _next_run_id()
    threads = []
    for _label, args in _port_scan_specs():
        command = " ".join(["nmap"] + args + [ip])
        job = _new_job("1", name, command, run)
        t = threading.Thread(target=_run_port_pass, args=(job, args, ip, deadline), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _start_port_enum(ip: str, minutes: int) -> None:
    """Launch port enumeration in the background; the menu stays free."""
    threading.Thread(target=_run_port_enum, args=(ip, minutes), daemon=True).start()


# ── service detection (phase 3) ───────────────────────────────────────────────
# Deep identification on the open ports from phase 2: -sV probes real versions and
# -sC runs the default NSE scripts (titles, certs, SMB/SSH/HTTP info) — the payload
# of this phase. OS detection runs as its OWN scan (`-O --osscan-guess`, root only)
# because -O needs an open AND a closed port, so it must not be pinned to the open-
# port list (that yields nmap's "OS detection unreliable" warning). -A is avoided for
# the same reason (its bundled -O would be unreliable) plus its traceroute noise.
def _service_scan_specs(ip: str) -> list:
    """(label, nmap-args) for service detection on ``ip``'s known-open ports. TCP gets
    -sV -sC; UDP (root) gets -sU -sV; OS (root) gets its own unrestricted -O scan."""
    ports = fetch_ports(ip)
    tcp = [str(p) for p, proto, _s in ports if proto == "tcp"]
    udp = [str(p) for p, proto, _s in ports if proto == "udp"]
    specs = []
    if tcp:
        specs.append(("service", ["-sV", "-sC", "-Pn", "-n", "-T4", "-p", ",".join(tcp)]))
    if udp and _is_root():
        specs.append(("service-udp", ["-sU", "-sV", "-Pn", "-n", "-T4", "-p", ",".join(udp)]))
    if _is_root():
        specs.append(("os", ["-O", "--osscan-guess", "-Pn", "-n", "-T4"]))
    return specs


def _run_service_pass(job: dict, args: list, ip: str, deadline: float) -> None:
    """Run one service-detection scan, streaming probed services / NSE output / OS to
    the DB. Honours job['cancel']; persists progress and captured output."""
    counter = [0]

    def _on_items(batch):
        for h in batch:
            if _is_self_ip(h["ip"]):
                continue
            svc, scr, os_name = h.get("services") or [], h.get("scripts") or [], h.get("os")
            if svc:
                save_services(h["ip"], svc)
            if scr:
                save_scripts(h["ip"], scr)            # also extracts cert/redirect/SMB hostnames
            if h.get("hostnames"):
                save_hostnames(h["ip"], h["hostnames"])
            if os_name:
                save_os(h["ip"], os_name)
            counter[0] += len(svc) + len(scr) + (1 if os_name else 0)
            job["hosts"] = counter[0]
            _job_update(job)

    try:
        items, output = _run_nmap(args, [ip], _on_items, deadline=deadline,
                                  should_stop=job["cancel"].is_set,
                                  parse_elem=_host_detail_from_elem)
        job["output"] = output
        if items is None:
            job["state"], job["error"] = "error", "nmap not found"
        elif job["cancel"].is_set():
            job["state"] = "aborted"
        else:
            job["state"] = "done"
    except Exception as exc:
        job["state"], job["error"] = "error", str(exc)
    finally:
        _job_update(job)


def _run_service_detection(ip: str, minutes: int) -> None:
    """Concurrent service-detection scans on one host, sharing one time budget."""
    _refresh_own_addresses()
    save_hosts([{"ip": ip}])
    deadline = max(1, minutes * 60)
    name = _PHASES["2"][0]
    run = _next_run_id()
    threads = []
    for _label, args in _service_scan_specs(ip):
        command = " ".join(["nmap"] + args + [ip])
        job = _new_job("2", name, command, run)
        t = threading.Thread(target=_run_service_pass, args=(job, args, ip, deadline), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _start_service_detection(ip: str, minutes: int) -> None:
    """Launch service detection in the background; the menu stays free."""
    threading.Thread(target=_run_service_detection, args=(ip, minutes), daemon=True).start()


# ── vuln scan (phase 4) ───────────────────────────────────────────────────────
# Targeted NSE, driven by the services already in the DB — not a blind --script vuln.
# For each open port we look up its service and fire only the relevant checks: active
# CVE tests (vuln category) plus auth-weakness checks (anonymous / empty / default
# creds — the auth category, never brute). All script names are verified to ship with
# nmap. brute / dos / exploit are excluded; rdp-vuln-ms12-020 (can crash a host) is
# left out by default. SSL scripts run on any TLS-wrapped port. Findings in the
# standard NSE `vuln` format (State: VULNERABLE) are parsed into the vulns table.
_SSL = "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params"
_VULN_SCRIPTS = {
    "microsoft-ds": "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-vuln-ms10-061,smb-vuln-cve2009-3103,smb-double-pulsar-backdoor,"
                    "smb-security-mode,smb2-security-mode,smb-enum-users",
    "netbios-ssn":  "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-security-mode,smb-enum-users",
    "http":         "http-shellshock,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
                    "http-vuln-cve2014-3704,http-vuln-cve2012-1823,http-vuln-cve2017-1001000,"
                    "http-vuln-misfortune-cookie,http-default-accounts,http-auth-finder,"
                    "http-config-backup,http-git,http-webdav-scan",
    "ms-wbt-server": "rdp-ntlm-info",
    "ftp":          "ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-anon",
    "ssh":          "ssh-auth-methods,ssh-publickey-acceptance",
    "telnet":       "telnet-encryption",
    "smtp":         "smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764",
    "mysql":        "mysql-vuln-cve2012-2122,mysql-empty-password",
    "ms-sql":       "ms-sql-empty-password",
    "oracle":       "oracle-enum-users",
    "mongodb":      "mongodb-databases",
    "redis":        "redis-info",
    "vnc":          "realvnc-auth-bypass,vnc-info,vnc-title",
    "snmp":         "snmp-info",
    "x11":          "x11-access",
    "rmi":          "rmi-vuln-classloader",
    "rsync":        "rsync-list-modules",
    "distcc":       "distcc-cve2004-2687",
    "clamav":       "clamav-exec",
    "irc":          "irc-unrealircd-backdoor",
}
_VULN_PORT_FALLBACK = {
    445: "microsoft-ds", 139: "netbios-ssn", 80: "http", 443: "http", 8080: "http",
    8443: "http", 3389: "ms-wbt-server", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    465: "smtp", 587: "smtp", 3306: "mysql", 1433: "ms-sql", 1521: "oracle",
    27017: "mongodb", 6379: "redis", 5900: "vnc", 161: "snmp", 1099: "rmi", 873: "rsync",
    3632: "distcc", 3310: "clamav", 6667: "irc", 6000: "x11", 6001: "x11",
}
_TLS_PORTS = {443, 465, 563, 636, 853, 990, 992, 993, 995, 8443}
# auth-category scripts that only emit output when they actually find a weakness, so
# any output is a finding (anonymous / empty / default creds, unauth access).
_AUTH_FINDING = {"ftp-anon", "mysql-empty-password", "ms-sql-empty-password",
                 "http-default-accounts", "x11-access", "redis-info",
                 "mongodb-databases", "rsync-list-modules", "snmp-info"}


def _vuln_key(name: "str | None", port: int) -> "str | None":
    if name:
        low = name.lower()
        for key in _VULN_SCRIPTS:
            if key in low:
                return key
    return _VULN_PORT_FALLBACK.get(port)


def _vuln_families(ip: str) -> list:
    """Group the host's open ports into (label, scripts, [ports]) families so each
    family runs one targeted scan. SSL scripts are added for TLS-wrapped ports."""
    services = fetch_services(ip)
    groups: dict = {}    # key -> [scripts, set(ports)]
    for port, proto, _state in fetch_ports(ip):
        name = (services.get((port, proto)) or (None, None, None))[0]
        key = _vuln_key(name, port)
        if key:
            groups.setdefault(key, [_VULN_SCRIPTS[key], set()])[1].add(port)
        low = (name or "").lower()
        if port in _TLS_PORTS or "ssl" in low or "https" in low or "tls" in low:
            groups.setdefault("ssl", [_SSL, set()])[1].add(port)
    return [(k, sc, sorted(ps)) for k, (sc, ps) in groups.items() if ps]


# Auth-category scripts whose mere output is a weakness → a one-line title each.
_AUTH_TITLE = {
    "ftp-anon": "anonymous FTP login allowed",
    "mysql-empty-password": "MySQL account with empty password",
    "ms-sql-empty-password": "MSSQL account with empty password",
    "http-default-accounts": "default web credentials found",
    "x11-access": "X11 server open (no auth)",
    "redis-info": "Redis reachable without auth",
    "mongodb-databases": "MongoDB reachable without auth",
    "rsync-list-modules": "rsync modules listable",
    "snmp-info": "SNMP readable (default community)",
}


def _extract_finding(sid: str, output: str) -> "dict | None":
    """Turn one NSE script result into a finding, or None. Covers three sources with
    no re-scan (the output is already in the DB): the standard `vuln` library format
    (State: VULNERABLE / LIKELY), auth scripts whose output implies a weakness, and a
    few info rules over -sC output (exposed .git, weak TLS, SMB signing, …)."""
    if not output:
        return None
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", output)))
    cve = ",".join(cves) or None

    # 1) standard vuln library format
    if re.search(r"State:\s*VULNERABLE", output):
        state = "VULNERABLE"
    elif re.search(r"State:\s*LIKELY VULNERABLE", output):
        state = "LIKELY"
    else:
        state = None
    if state:
        m = re.search(r"Risk factor:\s*([A-Za-z]+)", output)
        risk = (m.group(1).upper() if m else "HIGH")
        # title = the line right after "VULNERABLE:" (the human name), if it isn't a
        # structured field; otherwise fall back to the script id.
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        summary = sid
        for i, ln in enumerate(lines):
            if re.match(r"(LIKELY )?VULNERABLE:?$", ln, re.I) and i + 1 < len(lines):
                nxt = lines[i + 1]
                if not re.match(r"(State|IDs|Risk|Disclosure|References|Description|Extra)\b", nxt):
                    summary = nxt
                break
        return {"state": state, "cve": cve, "risk": risk, "summary": summary[:140]}

    # 2) auth-category scripts: any output = weakness
    if sid in _AUTH_TITLE:
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH", "summary": _AUTH_TITLE[sid]}

    # 2b) http-headers tool: fold the tech banner + missing security headers into one finding
    if sid == "http-headers":
        tech = []
        for hdr in ("Server", "X-Powered-By"):
            m = re.search(rf"^{hdr}:\s*(.+)$", output, re.I | re.M)
            if m:
                tech.append(m.group(1).strip())
        wanted = [("content-security-policy", "CSP"), ("x-frame-options", "X-Frame-Options"),
                  ("x-content-type-options", "X-Content-Type-Options")]
        if re.match(r"\s*https://", output, re.I):          # HSTS only matters over TLS
            wanted.append(("strict-transport-security", "HSTS"))
        missing = [short for hdr, short in wanted
                   if not re.search(rf"^{re.escape(hdr)}:", output, re.I | re.M)]
        parts = []
        if tech:
            parts.append("tech: " + ", ".join(tech))
        if missing:
            parts.append("missing sec-headers: " + ", ".join(missing))
        if parts:
            return {"state": "INFO", "cve": cve, "risk": "LOW" if missing else "INFO",
                    "summary": " · ".join(parts)[:140]}
        return None

    # 3) info rules over -sC output
    low = output.lower()
    info = None
    if sid == "http-git":
        info = ("exposed .git repository", "MEDIUM")
    elif sid == "http-config-backup":
        info = ("exposed config/backup file", "MEDIUM")
    elif sid == "http-methods" and re.search(r"\b(PUT|DELETE|TRACE|CONNECT)\b", output):
        info = ("risky HTTP methods enabled", "LOW")
    elif sid in ("http-title", "http-ls") and "index of /" in low:
        info = ("directory listing enabled", "LOW")
    elif sid == "ssl-cert" and ("self-signed" in low or "self signed" in low):
        info = ("self-signed TLS certificate", "LOW")
    elif sid == "ssl-enum-ciphers" and re.search(r"least strength:\s*[C-F]", output):
        info = ("weak TLS ciphers", "MEDIUM")
    elif sid in ("smb-security-mode", "smb2-security-mode") and "not required" in low:
        info = ("SMB message signing not required", "MEDIUM")
    elif sid == "ssh-auth-methods" and "password" in low:
        info = ("SSH password authentication enabled", "INFO")
    if info:
        return {"state": "INFO", "cve": cve, "risk": info[1], "summary": info[0]}
    return None


def _run_vuln_pass(job: dict, scripts: str, ports: list, ip: str, deadline: float) -> None:
    """Run one family's targeted vuln/auth scan, streaming script output (to scripts)
    and parsed findings (to vulns) to the DB. Honours job['cancel']."""
    args = ["-sV", "--script", scripts, "-Pn", "-n", "-T3",
            "--script-timeout", "120s", "-p", ",".join(str(p) for p in ports)]

    def _on_items(batch):
        for h in batch:
            if _is_self_ip(h["ip"]):
                continue
            if h.get("scripts"):
                save_scripts(h["ip"], h["scripts"])     # also extracts findings -> vulns
            if h.get("services"):
                save_services(h["ip"], h["services"])
            job["hosts"] = len(fetch_vulns(h["ip"]))     # count of findings so far
            _job_update(job)

    try:
        items, output = _run_nmap(args, [ip], _on_items, deadline=deadline,
                                  should_stop=job["cancel"].is_set,
                                  parse_elem=_host_detail_from_elem)
        job["output"] = output
        if items is None:
            job["state"], job["error"] = "error", "nmap not found"
        elif job["cancel"].is_set():
            job["state"] = "aborted"
        else:
            job["state"] = "done"
    except Exception as exc:
        job["state"], job["error"] = "error", str(exc)
    finally:
        _job_update(job)


def _run_vuln_scan(ip: str, minutes: int) -> None:
    """One concurrent targeted scan per service family, sharing one time budget."""
    _refresh_own_addresses()
    save_hosts([{"ip": ip}])
    deadline = max(1, minutes * 60)
    name = _PHASES["3"][0]
    families = _vuln_families(ip)
    if not families:
        job = _new_job("3", name, f"nmap (no known services on {ip})")
        job["state"] = "done"
        _job_update(job)
        return
    run = _next_run_id()
    threads = []
    for label, scripts, ports in families:
        command = f"nmap -sV --script {scripts} -T3 -p {','.join(str(p) for p in ports)} {ip}"
        job = _new_job("3", f"{name} · {label}", command, run)
        t = threading.Thread(target=_run_vuln_pass, args=(job, scripts, ports, ip, deadline),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _start_vuln_scan(ip: str, minutes: int) -> None:
    """Launch the vuln scan in the background; the menu stays free."""
    threading.Thread(target=_run_vuln_scan, args=(ip, minutes), daemon=True).start()


# ── CVE lookup (phase 5) ──────────────────────────────────────────────────────
# Offline enrichment: the service-detection phase stores a CPE per port; here we
# match that CPE (vendor/product + version) against the local NVD-derived index
# (appdata/cve_index.db) and record the known CVE numbers as findings. No network,
# no scanning — pure lookup. Only versioned CPEs are used (a general CPE without a
# version can't be mapped precisely and would produce false positives).
_CVE_STORE_CAP = 20        # newest CVEs kept per service (keeps findings readable)

# The same product often carries a different CPE vendor/product in nmap output than
# the one(s) NVD files its CVEs under. Map the nmap pair to the canonical NVD pair(s)
# that actually hold the CVEs; the lookup queries the original AND every alias and
# unions the results, so nothing is silently missed (some products span two vendors,
# e.g. rabbitmq under pivotal_software and broadcom).
_CPE_ALIAS = {
    ("mysql", "mysql"):                 [("oracle", "mysql")],
    ("nginx", "nginx"):                 [("f5", "nginx")],
    ("igor_sysoev", "nginx"):           [("f5", "nginx")],
    ("elasticsearch", "elasticsearch"): [("elastic", "elasticsearch")],
    ("squid", "squid"):                 [("squid-cache", "squid")],
    ("isc", "bind9"):                   [("isc", "bind")],
    ("vsftpd", "vsftpd"):               [("redhat", "vsftpd")],
    ("proftpd", "proftpd"):             [("proftpd_project", "proftpd")],
    ("rabbitmq", "rabbitmq"):           [("pivotal_software", "rabbitmq"),
                                         ("broadcom", "rabbitmq_server")],
    ("pureftpd", "pureftpd"):           [("pureftpd", "pure-ftpd")],
}


def _ver_key(v: "str | None") -> tuple:
    """Version as a tuple of its numeric components, e.g. '8.2p1' → (8, 2, 1).
    Good enough to order/compare the version strings NVD uses in its ranges."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _ver_cmp(a: "str | None", b: "str | None") -> int:
    """-1 / 0 / 1 comparing two version strings by their numeric components."""
    ta, tb = _ver_key(a), _ver_key(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _cve_sort_key(cve: str) -> tuple:
    """Sort CVE ids newest-first (by year, then sequence)."""
    m = re.match(r"CVE-(\d+)-(\d+)", cve)
    return (-int(m.group(1)), -int(m.group(2))) if m else (0, 0)


def _cpe_parts(cpe: "str | None") -> "tuple | None":
    """(vendor, product, version) from a CPE 2.2 (cpe:/a:v:p:ver) or 2.3
    (cpe:2.3:a:v:p:ver:…) URI. version is None when absent/any ('*'/'-')."""
    if not cpe or not cpe.startswith("cpe:"):
        return None
    body = cpe[4:]
    if body.startswith("/"):                       # 2.2
        f = body[1:].split(":")
    elif body.startswith("2.3:"):                  # 2.3
        f = body[4:].split(":")
    else:
        return None
    if len(f) < 3:
        return None
    vendor, product = f[1], f[2]
    version = f[3] if len(f) > 3 else None
    version = None if version in ("", "*", "-") else version
    if not vendor or not product:
        return None
    return vendor, product, version


def _ver_in_match(version: str, exact, vsi, vse, vei, vee) -> bool:
    """True when ``version`` satisfies one NVD cpeMatch row — deliberately strict, to
    show fewer but better-verified CVEs (less noise) rather than everything NVD lists:

      • exact version: matched only when the fingerprint is at least as precise as the
        exact value (so a bare major like '4' is NOT taken as '4.0.0' and does not match
        every '4.x' exact row — the biggest false-positive source).
      • ranges: only *closed* ranges (a start bound AND an end bound) count, and only for
        a fingerprint with ≥2 numeric components. Open-ended rows ('< X' / '>= X' only,
        or 'all versions') are dropped — they match huge, cross-branch swaths of versions.
    """
    vk = _ver_key(version)
    if exact:
        ek = _ver_key(exact)
        if len(vk) < len(ek):
            return False                   # fingerprint too coarse to claim this version
        n = max(len(vk), len(ek))
        return vk + (0,) * (n - len(vk)) == ek + (0,) * (n - len(ek))
    if len(vk) < 2:
        return False                       # bare major — too coarse to place in a range
    if not ((vsi or vse) and (vei or vee)):
        return False                       # open-ended / unbounded range — dropped
    if vsi and _ver_cmp(version, vsi) < 0:
        return False
    if vse and _ver_cmp(version, vse) <= 0:
        return False
    if vei and _ver_cmp(version, vei) > 0:
        return False
    if vee and _ver_cmp(version, vee) >= 0:
        return False
    return True


def _cve_lookup(vendor: str, product: str, version: str) -> "list | None":
    """Matching CVE ids (newest first) for one vendor/product/version, or None when
    the index is missing/unreadable. Queries the CPE pair plus any aliases (some
    products file CVEs under several NVD vendors) and unions the results."""
    if not os.path.exists(CVE_INDEX_PATH):
        return None
    targets = [(vendor, product)] + _CPE_ALIAS.get((vendor, product), [])
    try:
        con = sqlite3.connect(CVE_INDEX_PATH)
        try:
            rows = []
            for v, p in targets:
                rows += con.execute(
                    "SELECT m.exact_ver, m.vsi, m.vse, m.vei, m.vee, m.cve "
                    "FROM cve_match m JOIN product p ON p.id = m.product_id "
                    "WHERE p.vendor = ? AND p.product = ?", (v, p)).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    matched = {cve for exact, vsi, vse, vei, vee, cve in rows
               if _ver_in_match(version, exact, vsi, vse, vei, vee)}
    return sorted(matched, key=_cve_sort_key)


def _run_cve_lookup(ip: str) -> list:
    """Per versioned service CPE on the host, the CVEs it maps to.
    Returns [(port, proto, product, version, [cve, …]), …]."""
    results = []
    for (port, proto), (_name, product_s, version_s, cpe) in sorted(fetch_services(ip).items()):
        parts = _cpe_parts(cpe)
        if not parts:
            continue
        vendor, product, cpe_ver = parts
        version = cpe_ver or version_s
        if not version or not re.search(r"\d", version):
            continue                               # need a concrete version
        cves = _cve_lookup(vendor, product, version)
        if cves:
            results.append((port, proto, product, version, cves))
    return results


def save_cve_findings(ip: str, results: list) -> None:
    """Replace this host's CVE-lookup findings in the vulns table (script
    'cve-lookup', one row per port), so re-running the phase stays idempotent."""
    if not ip or _is_self_ip(ip):
        return
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            conn.execute("DELETE FROM vulns WHERE ip = ? AND script = 'cve-lookup'", (ip,))
            for port, proto, product, version, cves in results:
                cve_str = ",".join(cves[:_CVE_STORE_CAP])
                summary = f"{product} {version} — {len(cves)} known CVE(s)"
                conn.execute(
                    "INSERT INTO vulns (ip, port, proto, script, state, cve, risk, summary, "
                    "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ip, port, proto, "cve-lookup", "CVE", cve_str, "INFO", summary, now, now))
            conn.commit()
        finally:
            conn.close()


def _do_cve_lookup(ip: str) -> None:
    """Run the offline lookup for one host, store findings, log a job, print a recap."""
    name = _PHASES["4"][0]
    job = _new_job("4", f"{name} · {ip}", f"cve-index lookup (offline NVD) for {ip}")
    results = []
    try:
        results = _run_cve_lookup(ip)
        save_cve_findings(ip, results)
        lines = [f"CVE lookup — {ip} (offline NVD index)"]
        for port, proto, product, version, cves in results:
            lines.append(f"{port}/{proto}  {product} {version}  {len(cves)} CVE")
            shown = cves[:_CVE_STORE_CAP]
            lines.append("  " + ", ".join(shown)
                         + (f"  (+{len(cves) - len(shown)} more)" if len(cves) > len(shown) else ""))
        job["output"], job["hosts"], job["state"] = "\n".join(lines), len(results), "done"
    except Exception as exc:
        job["state"], job["error"] = "error", str(exc)
    finally:
        _job_update(job)

    if not results:
        print(f"\n{DIM}▸ CVE lookup — {ip}: no versioned service CPE matched the index "
              f"(run {BOLD}[2] Service detection{RESET}{DIM} first, or no known CVEs){RESET}")
        return
    total = sum(len(cves) for *_rest, cves in results)
    print(f"\n{GREEN}▶ CVE lookup done{RESET} {DIM}({ip} · {len(results)} service(s), {total} CVE) — "
          f"see {BOLD}[f] findings{RESET}{DIM} · {BOLD}[s] status{RESET}")


def _handle_cve_lookup() -> None:
    """Phase 5 flow: read a target IP and match its service CPEs to known CVEs."""
    if not os.path.exists(CVE_INDEX_PATH):
        print(f"\n{YELLOW}⚠ CVE index not found{RESET} {DIM}({os.path.basename(CVE_INDEX_PATH)}) "
              f"— build it with the installer's NVD step, then retry{RESET}")
        return
    while True:
        value = _ctx_ask("cve", "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        if not fetch_services(ip):
            print(f"{DIM}note: no services recorded for {ip} — run {BOLD}[2] Service "
                  f"detection{RESET}{DIM} first{RESET}")
            continue
        _do_cve_lookup(ip)
        return


# ── progress (per-host workflow tracker) ──────────────────────────────────────
def _host_job_states(ip: str) -> dict:
    """Aggregated command-history state per phase for one host. A phase spawns several
    commands (parallel nmap passes / script families), so its state is combined across
    all of them: 'running' while ANY is still running, and only settling to
    'done'/'error'/'aborted' once they have all finished — so progress never flips to
    complete mid-scan. A job belongs to the host when the IP appears as a whole token in
    its command or name."""
    pat = re.compile(r"(?<!\d)" + re.escape(ip) + r"(?!\d)")
    with _JOBS_LOCK:
        jobs = list(_JOBS)
    per_phase: dict = {}
    for j in jobs:
        if pat.search(j.get("command") or "") or pat.search(j.get("name") or ""):
            per_phase.setdefault(j["phase"], []).append(j["state"])
    return {phase: _agg_state(sts) for phase, sts in per_phase.items()}


def _agg_state(states: list) -> str:
    """Combine several command states into one: 'running' while any is still going;
    else a success ('done') settles it; 'error'/'aborted' only when nothing completed."""
    if "running" in states:
        return "running"
    if "done" in states:
        return "done"
    if "error" in states:
        return "error"
    if "aborted" in states:
        return "aborted"
    return states[-1] if states else "done"


def _render_host_progress(ip: str) -> None:
    """Per-host workflow tracker: for every phase, show whether it has run for this host
    (evidence in the DB) and its current state from the command history — so it's clear
    what's complete, what's mid-run and what hasn't been done yet."""
    known = any(r[0] == ip for r in fetch_hosts())
    ports = fetch_ports(ip)
    services = fetch_services(ip)
    host_scripts = fetch_scripts(ip, 0, "")
    scripted = fetch_scripted_ports(ip)
    vulns = fetch_vulns(ip)
    # Phase 3's -sC feeds the same vulns table (http-methods, ssl-cert… all state INFO),
    # so findings alone don't prove the vuln scan ran. Count only what the vuln category
    # emits and -sC does not — VULNERABLE/LIKELY; a phase-4 job (persisted) also marks it.
    vuln_findings = [v for v in vulns if v[3] in ("VULNERABLE", "LIKELY")]   # phase 4
    cve_findings = [v for v in vulns if v[3] == "CVE"]       # phase 5
    n_cve = sum(len([c for c in (v[4] or "").split(",") if c.strip()]) for v in cve_findings)
    jobstate = _host_job_states(ip)

    # Phase 2 (port scan) already seeds the services table with nmap's port->name
    # guesses, so a bare name doesn't prove phase 3 ran. Service detection (-sV -sC) is
    # what adds a product/version/CPE or NSE script output — that's the real evidence.
    fingerprinted = [s for s in services.values() if s[1] or s[2] or s[3]]

    # Phase 2 also re-registers the host (save_hosts), so "on record" alone doesn't mean
    # host discovery ran. Prefer the discovery job's own record: if a discovery pass ran
    # this session (its found-set is populated), phase 1 counts only when it found THIS
    # host. With no live discovery job (e.g. a prior session), fall back to "on record".
    with _JOBS_LOCK:
        disc = [j for j in _JOBS if j["phase"] == "0"]
        discovered = any(ip in j["found"] for j in disc)
        live_discovery = any(j["found"] for j in disc)
    phase0_done = discovered or (known and not live_discovery)

    # phase 5 (service exploitation) is complete only when EVERY service's checklist is
    # resolved (done/skip); phase 6 (privesc) when its OS checklist is resolved.
    targets = _exploit_targets(ip)
    n_svc_done = sum(1 for p, pr, _l, k, _v, _s in targets if _service_steps_complete(ip, p, pr, k))
    phase5_done = bool(targets) and n_svc_done == len(targets)
    privesc_done, privesc_detail = _os_checklist_progress(ip, "privesc", _PRIVESC_STEPS)
    persist_done, persist_detail = _os_checklist_progress(ip, "persist", _PERSIST_STEPS)
    cover_done, cover_detail = _os_checklist_progress(ip, "cover", _COVER_STEPS)

    # phase key -> (has evidence in the DB, short detail line)
    evidence = {
        "0": (phase0_done, "on record" if phase0_done else ""),
        "1": (bool(ports), f"{len(ports)} open port(s)" if ports else ""),
        "2": (bool(fingerprinted) or bool(host_scripts) or bool(scripted),
              f"{len(fingerprinted)} fingerprinted" if fingerprinted else ("NSE output" if (host_scripts or scripted) else "")),
        "3": (bool(vuln_findings), f"{len(vuln_findings)} vuln finding(s)" if vuln_findings else ""),
        "4": (bool(cve_findings), f"{n_cve} CVE" if cve_findings else ""),
        "5": (phase5_done, f"{n_svc_done}/{len(targets)} services" if targets else ""),
        "6": (privesc_done, privesc_detail),
        "7": (persist_done, persist_detail),
        "8": (cover_done, cover_detail),
    }

    print(f"\n{BOLD}{ip} — progress{RESET}")
    if not known and not ports and not vulns and not jobstate:
        print(f"  {DIM}nothing recorded for this host yet — run {BOLD}[0] Host discovery{RESET}"
              f"{DIM} / {BOLD}[1] Port enumeration{RESET}{DIM} first{RESET}")
        return

    done = 0
    for key, name, _desc in PHASES:
        has, detail = evidence[key]
        # phases 5-8 are manual checklists (no background jobs) — completion is driven by
        # the checklist evidence above, not job state.
        st = None if key in ("5", "6", "7", "8") else jobstate.get(key)
        if st == "running":
            sym, col, label = "⏳", YELLOW, "running"
        elif has or st == "done":
            sym, col, label = "✓", GREEN, "complete"
            done += 1
        elif st == "error":
            sym, col, label = "✗", RED, "error"
        elif st == "aborted":
            sym, col, label = "⊘", MAGENTA, "aborted"
        else:
            sym, col, label = "○", DIM, "not run"
        extra = f"  {DIM}· {detail}{RESET}" if detail else ""
        print(f"  {col}{sym} [{key}] {name:<20}{RESET} {col}{label:<9}{RESET}{extra}")
    print(f"\n  {DIM}{done}/{len(PHASES)} phase(s) complete{RESET}")


def _launch_phase_for(key: str, ip: str) -> None:
    """Run one workflow phase for a host chosen in the progress view — same launch path
    as the per-phase handlers, but the IP is already known so it's not re-typed."""
    if key == "0":
        print(f"{DIM}note: host discovery scans a subnet/range, not one host — use "
              f"{BOLD}[0]{RESET}{DIM} from the menu{RESET}")
        return
    if key == "8":
        _os_checklist_for(ip, "cover", "Covering Tracks", _COVER_STEPS)
        return
    if key == "7":
        _os_checklist_for(ip, "persist", "Persistence", _PERSIST_STEPS)
        return
    if key == "6":
        _os_checklist_for(ip, "privesc", "Privilege Escalation", _PRIVESC_STEPS)
        return
    if key == "5":
        _exploit_targets_view(ip)                            # service exploitation checklist
        return
    if key == "4":
        if not os.path.exists(CVE_INDEX_PATH):
            print(f"\n{YELLOW}⚠ CVE index not found{RESET} {DIM}({os.path.basename(CVE_INDEX_PATH)}) "
                  f"— build it with the installer's NVD step, then retry{RESET}")
            return
        if not fetch_services(ip):
            print(f"{DIM}note: no services recorded for {ip} — run {BOLD}[2] Service "
                  f"detection{RESET}{DIM} first{RESET}")
            return
        _do_cve_lookup(ip)
        return
    # phases 1–3: background nmap scans on a time budget
    if key == "2" and not fetch_ports(ip):
        print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[1] Port "
              f"enumeration{RESET}{DIM} first (OS scan still runs if root){RESET}")
    if key == "3" and not fetch_ports(ip):
        print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[1] Port "
              f"enumeration{RESET}{DIM} (and {BOLD}[2] Service detection{RESET}{DIM}) first{RESET}")
        return
    name = _PHASES[key][0]
    if key == "3":
        print(f"{DIM}vuln + auth scripting{RESET}")
    module = {"1": "ports", "2": "service", "3": "vuln"}[key]
    minutes = _prompt_minutes(module, name, ip)
    if minutes is None:
        return
    if key == "1":
        _start_port_enum(ip, minutes)
        detail = "fast + full TCP + UDP"
    elif key == "2":
        _start_service_detection(ip, minutes)
        detail = "-sV -sC + OS"
    else:
        _start_vuln_scan(ip, minutes)
        detail = "targeted NSE vuln+auth"
    print(f"\n{GREEN}▶ {name.lower()} running in the background{RESET} "
          f"{DIM}({ip} · {detail}, ⏱ {minutes}m) — check {BOLD}[s] status{RESET}")


def _open_host_progress(ip: str) -> None:
    """Interactive progress view for a known host: run a phase by number, or jump to its
    findings with [f]. Reused from the database (p <n>) and the host's other sub-views."""
    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v == "f":
            _host_findings_view(ip)
            return "refresh"
        if v == "s":
            _status_view()
            return "refresh"
        if v in _PHASES:
            _launch_phase_for(v, ip)
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> run phase · f · s · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}/progress",
              "[Enter] refresh · <n> run phase · [f] findings · [s] status · [b] back · [m] menu",
              lambda: _render_host_progress(ip), _handle)


# ── service exploitation (phase 6) ────────────────────────────────────────────
# Services are triaged in CTF/OSCP order: the ones that most often give a fast foothold
# or rich enumeration come first, so you know what to hit first. Each entry is
#   (key, label, {typical ports}, (match tokens for cpe/product/name, all lowercased)).
# A service's class is resolved by the cascade CPE → product/version → service name →
# port default — strongest signal first, port number only as a last resort.
_EXPLOIT_SERVICES = [
    ("http",    "HTTP / web app",     {80, 81, 443, 591, 2082, 2087, 3000, 5000, 5601,
                                       7001, 8000, 8008, 8080, 8081, 8443, 8500, 8888,
                                       9000, 9090, 15672},
     ("http", "https", "ssl/http", "nginx", "apache", "httpd", "iis", "tomcat",
      "jetty", "lighttpd", "werkzeug", "gunicorn", "express", "haproxy", "caddy")),
    ("smb",     "SMB / file shares",  {137, 138, 139, 445},
     ("smb", "microsoft-ds", "netbios-ssn", "netbios", "samba", "cifs")),
    ("winrm",   "WinRM (remote shell)", {5985, 5986}, ("winrm", "wsman")),
    ("ftp",     "FTP",                {21, 990, 2121},
     ("ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla", "ftpd")),
    ("tftp",    "TFTP (UDP)",         {69}, ("tftp",)),
    ("nfs",     "NFS / RPC mounts",   {111, 2049},
     ("nfs", "rpcbind", "portmap", "mountd")),
    ("afp",     "AFP (Apple shares)", {548}, ("afp", "netatalk", "apple filing")),
    ("rsync",   "rsync",              {873}, ("rsync",)),
    ("distcc",  "distcc (RCE)",       {3632}, ("distcc",)),
    ("redis",   "Redis",              {6379, 6380}, ("redis",)),
    ("memcached", "Memcached",        {11211}, ("memcache",)),
    ("elastic", "Elasticsearch",      {9200, 9300}, ("elasticsearch", "elastic")),
    ("mongodb", "MongoDB",            {27017, 27018}, ("mongodb", "mongod", "mongo")),
    ("couchdb", "CouchDB",            {5984, 6984}, ("couchdb",)),
    ("neo4j",   "Neo4j",              {7474, 7687}, ("neo4j",)),
    ("influxdb", "InfluxDB",          {8086}, ("influxdb", "influx")),
    ("amqp",    "AMQP / RabbitMQ",    {5672}, ("amqp", "rabbitmq")),
    ("epmd",    "Erlang epmd",        {4369}, ("epmd", "erlang port mapper")),
    ("docker",  "Docker API",         {2375, 2376}, ("docker",)),
    ("jdwp",    "Java JDWP (RCE)",    {8787}, ("jdwp", "java debug")),
    ("rmi",     "Java RMI",           {1050, 1098, 1099}, ("rmi", "jrmi")),
    ("clamav",  "ClamAV (RCE)",       {3310}, ("clamav",)),
    ("ajp",     "AJP / Tomcat (Ghostcat)", {8009}, ("ajp13", "ajp")),
    ("svn",     "SVN (svnserve)",     {3690}, ("svn", "subversion")),
    ("mysql",   "MySQL / MariaDB",    {3306}, ("mysql", "mariadb")),
    ("mssql",   "MS SQL Server",      {1433, 1434}, ("ms-sql", "mssql", "microsoft sql")),
    ("psql",    "PostgreSQL",         {5432}, ("postgresql", "postgres")),
    ("oracle",  "Oracle DB",          {1521, 1748, 1754, 1808, 1809, 2100},
     ("oracle", "tns")),
    ("mqtt",    "MQTT (IoT)",         {1883, 8883}, ("mqtt", "mosquitto")),
    ("ldap",    "LDAP / AD",          {389, 636, 3268, 3269}, ("ldap",)),
    ("kerberos", "Kerberos (AD)",     {88, 464}, ("kerberos", "kpasswd")),
    ("msrpc",   "MSRPC endpoint",     {135, 593}, ("msrpc", "epmap")),
    ("snmp",    "SNMP",               {161, 162}, ("snmp",)),
    ("ipmi",    "IPMI (hash leak)",   {623}, ("ipmi", "asf-rmcp")),
    ("dns",     "DNS",                {53}, ("domain", "dns", "bind")),
    ("smtp",    "SMTP / mail",        {25, 465, 587}, ("smtp",)),
    ("mail2",   "POP3 / IMAP",        {110, 143, 993, 995}, ("pop3", "imap")),
    ("telnet",  "Telnet",             {23}, ("telnet",)),
    ("irc",     "IRC",                {6660, 6667, 6669, 6697}, ("irc", "ircd", "unreal")),
    ("rdp",     "RDP",                {3389}, ("ms-wbt-server", "rdp", "terminal serv")),
    ("vnc",     "VNC",                {5900, 5901, 5902, 5903}, ("vnc",)),
    ("ssh",     "SSH",                {22, 2222}, ("ssh", "openssh", "dropbear")),
    ("squid",   "Squid proxy",        {3128}, ("squid",)),
    ("cups",    "CUPS / printing",    {631}, ("cups", "ipp")),
    ("jetdirect", "Printer (JetDirect/PJL)", {9100}, ("jetdirect", "pjl")),
    ("rservices", "BSD r-services",   {512, 513, 514}, ("rlogin", "rexec", "rsh", "rshd")),
    ("x11",     "X11",                {6000, 6001, 6002, 6003, 6004, 6005}, ("x11",)),
    ("finger",  "Finger",             {79}, ("finger",)),
    ("ident",   "ident (user enum)",  {113}, ("ident", "identd")),
    ("rtsp",    "RTSP (cameras)",     {554, 8554}, ("rtsp",)),
    ("sip",     "SIP / VoIP",         {5060, 5061}, ("sip",)),
    ("nntp",    "NNTP",               {119}, ("nntp",)),
]
_EXPLOIT_RANK = {key: i for i, (key, *_rest) in enumerate(_EXPLOIT_SERVICES)}
_EXPLOIT_UNKNOWN = ("other", "other / unknown")   # fallback bucket, always ranked last


# Per-service pentest checklist: the steps to work through once a service is picked in
# phase 6. Starter methodology (HTB/OSCP-flavoured) — each service gets a deeper, curated
# pass later. Keyed by the service class key; 'other' is the generic fallback.
_EXPLOIT_STEPS = {
    "http": [
        # ── fingerprint & recon ──
        ("HTTP headers, status & redirects (Server, X-Powered-By, cookies)", "http-headers"),
        "Fingerprint stack: whatweb / Wappalyzer / favicon hash → server, framework, CMS, versions",
        "TLS cert & redirects → extra hostnames / vhosts / emails; add them to /etc/hosts",
        "searchsploit the exact server / CMS / app versions (note every version you see)",
        # ── manual inspection ──
        "View-source + linked JS on every page → comments, endpoints, API routes, creds/keys",
        "robots.txt / sitemap.xml / .well-known + error pages → hidden paths & tech leaks",
        "Cookies & session: flags, predictable IDs; decode JWT, test alg:none / weak secret",
        # ── content discovery ──
        "Directory & file brute-force (feroxbuster / ffuf / gobuster) — ext php,asp,aspx,txt,bak,zip",
        "Hunt exposed VCS / backups / config: .git .svn .env web.config *.bak *~ config.php",
        "Vhost & subdomain fuzzing (ffuf -H 'Host:') — hidden apps often hold the vuln",
        "Hidden parameter discovery (arjun / ffuf) on dynamic endpoints",
        # ── authentication ──
        "Default / weak creds on every login and admin panel (admin:admin, product defaults)",
        "Auth bypass & user enumeration (SQLi ' or 1=1 --, verbose errors, response timing)",
        "Targeted brute-force (hydra) only if enumeration confirms users and no lockout",
        # ── injection & inclusion (OSCP core) ──
        "SQLi → auth bypass, UNION/error/blind dump; escalate to file read & RCE (xp_cmdshell / INTO OUTFILE / stacked)",
        "LFI / path traversal (/etc/passwd, web.config) → RCE via log poisoning, php://filter, /proc/self/environ",
        "RFI → include a remote webshell (allow_url_include)",
        "OS command injection (; | & ` $()) in every input → reverse shell",
        "SSTI ({{7*7}} / ${7*7}) → RCE (Jinja2 / Twig / Freemarker)",
        "File upload → webshell: bypass extension/MIME/magic (.phtml, double ext, null byte)",
        "XXE (XML input) & SSRF (reach internal services / 169.254.169.254 metadata)",
        "IDOR / broken access control — tamper IDs & roles to reach admin / other users",
        # ── known-app exploitation & foothold ──
        "CMS-specific scan (wpscan / droopescan) → vulnerable plugins, themes, versions",
        "Admin panel → RCE: upload plugin/theme, edit a template, or config code-exec",
        "Land a webshell / reverse shell; stabilise; loot DB creds & config for reuse",
    ],
    "smb": [
        # ── recon (no creds) ──
        "Null / guest session: enumerate shares, users (RID cycling), groups, password policy",
        "Identify the domain, the DC(s) and each host's exact OS & SMB dialect",
        "Version RCE: MS17-010 EternalBlue, MS08-067, SMBGhost CVE-2020-0796",
        # ── loot shares ──
        "Recursively read every readable share; grep for creds, keys, configs, backups",
        "SYSVOL / NETLOGON → GPP cpassword (Groups.xml), logon scripts, unattend.xml",
        # ── poison & relay (no creds) ──
        "Poison LLMNR / NBT-NS / mDNS → capture NetNTLMv1/v2 → crack or relay",
        "SMB signing 'not required' → NTLM relay to SMB / LDAP / ADCS-ESC8 (ntlmrelayx)",
        "Coerce auth (PetitPotam / PrinterBug / DFSCoerce / Coercer) → relay to escalate (RBCD / ADCS)",
        # ── DC-critical CVEs ──
        "On a DC: ZeroLogon CVE-2020-1472, noPac CVE-2021-42278/42287 → domain takeover",
        # ── creds → exec / dump ──
        "Spray creds & hashes across users and hosts (password reuse) — mind lockout",
        "Valid admin creds/hash → shell (psexec / wmiexec / smbexec; pass-the-hash)",
        "Dump SAM / LSA / LSASS / DPAPI (secretsdump); with rights → DCSync the domain",
        "Writable share → SCF / LNK / desktop.ini for hash capture, or stage a payload",
    ],
    "winrm": [
        "Confirm WinRM transport (5985 HTTP / 5986 HTTPS)",
        "Validate & spray creds and NTLM hashes against known users (watch lockout)",
        "Valid creds or hash → interactive shell (evil-winrm; -H for pass-the-hash)",
        "Needs 'Remote Management Users' / admin membership — note who has access",
        "Via the shell: enumerate, upload tooling, run commands; reuse creds to pivot",
    ],
    "ftp": [
        "Banner & exact version → searchsploit (vsftpd 2.3.4 backdoor, ProFTPD mod_copy CVE-2015-3306)",
        "Anonymous login (anonymous:<any>) → browse the tree",
        "Download everything; test write access (upload a throwaway file)",
        "Try known / default / reused creds; targeted brute only if lockout allows",
        "If FTP root maps to a web root or is writable → drop a webshell / poison a served file",
        "FTP-bounce (PORT) to reach & scan internal hosts through the server",
    ],
    "tftp": [
        "Confirm UDP/69 (no auth)",
        "GET well-known files: running-config / startup-config, backups, app configs",
        "Test PUT (arbitrary write) → overwrite a config or drop a payload",
        "Fuzz filenames from a wordlist — device configs often leak credentials",
    ],
    "nfs": [
        "List exports & allowed clients (showmount -e; nmap nfs-*)",
        "Mount each export; test read and write",
        "no_root_squash → plant a root-owned SUID binary for post-foothold privesc",
        "Match / forge local UID-GID to read restricted files (SSH keys, configs)",
        "NFSv4 hides exports from showmount — mount the root and browse",
    ],
    "afp": [
        "Enumerate shares & server info (afp-showmount / afp-serverinfo)",
        "Try guest / anonymous, then known creds",
        "Mount & hunt Time Machine backups, keychains and configs for creds",
    ],
    "rsync": [
        "List modules (rsync rsync://IP:873/)",
        "Access modules unauth; download everything, test upload to writable modules",
        "Read sensitive files (SSH keys, configs); write to a served/executable path if writable",
        "If auth is required, try known / reused creds",
    ],
    "distcc": [
        "Confirm distccd (3632)",
        "CVE-2004-2687 → arbitrary command execution (distcc_exec or manual DIST protocol)",
        "Use the RCE to read files / stage a reverse shell, then pivot to local privesc",
    ],
    "redis": [
        "Connect unauthenticated; note version, and INFO / CONFIG GET dir,dbfilename",
        "If auth required, try default / no password, then known creds (AUTH)",
        "Read keys for creds/sessions (KEYS *, GET)",
        "Writable dir → write an SSH key (CONFIG SET dir ~/.ssh, dbfilename authorized_keys)",
        "Writable web root → write a webshell via CONFIG SET dir + SAVE",
        "RCE via malicious module (MODULE LOAD) or master/slave replication (redis-rogue-server)",
    ],
    "memcached": [
        "stats / stats items / stats slabs / stats cachedump (unauthenticated)",
        "Dump all keys and values — hunt for sessions, tokens and creds",
    ],
    "elastic": [
        "GET / (version) and /_cat/indices?v — unauthenticated",
        "Dump indices & documents for creds and sensitive data (_search)",
        "Old versions → RCE (CVE-2014-3120, CVE-2015-1427 Groovy sandbox bypass)",
        "If auth is on, try default / known creds against the REST API and Kibana (5601)",
    ],
    "mongodb": [
        "Connect unauthenticated (mongosh); if refused, try default / known creds",
        "show dbs / show collections; dump interesting collections for creds",
        "Note version → searchsploit; check for exposed admin / config data",
    ],
    "couchdb": [
        "GET /_all_dbs and read documents unauthenticated; note version",
        "CVE-2017-12635 → create an admin user (privilege escalation)",
        "CVE-2017-12636 / EMONGO → RCE via query_server config; then reverse shell",
        "Erlang cookie reuse (with epmd) → node RCE",
    ],
    "neo4j": [
        "Browser/API on 7474; try default neo4j:neo4j and known creds",
        "Cypher queries to dump nodes/relationships for creds & data",
        "APOC / version RCE (e.g. CVE-2021-34371, apoc.* file & shell functions)",
    ],
    "influxdb": [
        "CVE-2019-20933 auth bypass (JWT signed with empty shared-secret)",
        "Enumerate databases (SHOW DATABASES) and dump measurements for creds/data",
        "If auth is on, try default / known creds against the HTTP API",
    ],
    "amqp": [
        "Try default guest:guest, then known creds",
        "Reach the management UI (15672) for queues, vhosts, users",
        "Enumerate & drain queues — messages often carry creds / internal data",
        "Erlang cookie (with epmd 4369) → node RCE on RabbitMQ",
    ],
    "epmd": [
        "List Erlang nodes & ports (epmd -names)",
        "Find / guess the Erlang cookie (~/.erlang.cookie, reused across nodes)",
        "Cookie → connect to the node and run erlang:os_cmd → RCE",
        "Common on RabbitMQ / CouchDB clusters — pivot into those",
    ],
    "docker": [
        "Confirm the unauthenticated Docker API (2375/2376)",
        "Enumerate: containers, images, networks (docker -H tcp://IP:2375 ps/images)",
        "Run a privileged container bind-mounting the host / → read/write host filesystem",
        "chroot the mount and add a user / SSH key / cron → root on the host",
        "Loot secrets from images, env vars and volumes",
    ],
    "jdwp": [
        "Confirm the JDWP handshake (Java Debug Wire Protocol)",
        "Any-context RCE via the debugger (jdwp-shellifier / manual breakpoint)",
        "Execute Runtime.exec → reverse shell as the JVM's user",
    ],
    "rmi": [
        "Enumerate the RMI registry — bound objects & remote methods (rmi-dumpregistry, BaRMIe)",
        "Java deserialization RCE against the endpoint (ysoserial gadget chains)",
        "JMX/RMI (if exposed) → MLet MBean → load a malicious MBean for RCE",
    ],
    "ajp": [
        "Confirm AJP13 (8009) and the fronting Tomcat",
        "Ghostcat CVE-2020-1938 → read WEB-INF/web.xml, configs, source",
        "Chain to RCE if you can upload a JSP into a served path (ajpy / metasploit)",
    ],
    "clamav": [
        "Confirm clamd (3310)",
        "Command execution via clamav-exec / known CVE (SCAN a crafted path)",
        "Use the RCE to stage a reverse shell as the clamav user",
    ],
    "svn": [
        "Enumerate over svn:// (svn ls / svn log / svn info)",
        "Checkout the repo; read commit history & diffs for secrets and creds",
        "svn cat / svn up -r<n> old revisions of removed sensitive files",
    ],
    "mysql": [
        "Try root with no password, then default / reused creds",
        "Version → searchsploit (e.g. CVE-2012-2122 auth bypass)",
        "Enumerate databases & users; dump app creds & password hashes",
        "Read local files with LOAD_FILE (needs FILE priv / secure_file_priv)",
        "Write a webshell with INTO OUTFILE into a writable web root",
        "UDF (lib_mysqludf_sys) for OS command execution if the plugin dir is writable",
    ],
    "mssql": [
        "Try sa with blank / default, then known creds (impacket mssqlclient / netexec mssql)",
        "Enable & use xp_cmdshell for OS command execution → reverse shell",
        "Enumerate linked servers; EXECUTE AS / trustworthy DB for privilege abuse",
        "Coerce the service account's NetNTLM hash (xp_dirtree / xp_fileexist) → crack / relay",
        "Read/write files (OPENROWSET / bulk); loot connection strings",
    ],
    "psql": [
        "Try postgres with blank / default, then known creds",
        "COPY … FROM/TO PROGRAM → OS command execution (9.3+) → reverse shell",
        "Read/write server files (pg_read_file / lo_import/lo_export / COPY)",
        "Enumerate databases & roles; dump app creds; check superuser",
    ],
    "oracle": [
        "Enumerate the SID (oracle-sid-brute / odat sidguesser)",
        "Brute default accounts (scott/tiger, system/manager, dbsnmp/dbsnmp) — odat passwordguesser",
        "With creds → file read/write, privesc and RCE via odat (dbmsscheduler / externaltable)",
        "TNS poisoning / version CVEs on older listeners",
    ],
    "mqtt": [
        "Connect anonymously and subscribe to all topics (# wildcard) — sniff for data/creds",
        "Enumerate topics & retained messages; look for device control / secrets",
        "Publish to control topics to influence devices; note impact",
        "If auth is on, try default / known creds against the broker",
    ],
    "ldap": [
        # ── enumerate ──
        "Anonymous / authenticated bind → dump users, groups, computers, OUs, trusts (ldapsearch / windapsearch)",
        "Read description / info / userPassword fields; extract naming context & password policy",
        "Map attack paths with BloodHound (LDAP collector) — ACLs, sessions, GPOs, delegation",
        # ── roast targets ──
        "Flag AS-REP (DONT_REQ_PREAUTH) and Kerberoast (servicePrincipalName) targets",
        # ── loot secrets from LDAP ──
        "Read LAPS (ms-Mcs-AdmPwd) and gMSA passwords (ReadGMSAPassword) where allowed",
        # ── ACL & object abuse (write rights) ──
        "ACL abuse: GenericAll/Write, WriteDACL/Owner, ForceChangePassword, AddMember (bloodyAD / dacledit)",
        "Shadow credentials: write msDS-KeyCredentialLink → PKINIT auth (pywhisker / certipy)",
        "RBCD: write msDS-AllowedToActOnBehalfOfOtherIdentity → S4U impersonation",
        # ── ADCS ──
        "Enumerate CA & templates (certipy find) → ESC1-ESC16 → cert as any user → PKINIT → DA",
        # ── relay / DCSync ──
        "Relay coerced auth to LDAP(S) when signing / channel-binding is off → RBCD / shadow cred",
        "With replication rights (DS-Replication-Get-Changes*) → DCSync all hashes",
    ],
    "kerberos": [
        # ── no creds ──
        "Enumerate valid users via AS-REQ (kerbrute userenum)",
        "AS-REP roast accounts with pre-auth disabled → crack offline",
        "Password-spray discovered users (Kerberos, lockout-aware)",
        # ── with creds ──
        "Kerberoast SPN accounts → crack service passwords offline",
        # ── delegation ──
        "Unconstrained delegation → coerce a DC/host & capture its TGT (printerbug + monitor)",
        "Constrained delegation → S4U2proxy to impersonate users to the allowed SPNs",
        "RBCD → S4U2self + S4U2proxy to mint a service ticket as any user",
        # ── ticket attacks ──
        "Overpass-the-hash (NT hash → TGT); pass-the-ticket to reuse tickets",
        "Silver ticket (service key) / golden ticket (krbtgt) / diamond ticket",
        # ── critical ──
        "noPac (CVE-2021-42278/42287) & MS14-068 → impersonate a DC / domain admin",
    ],
    "msrpc": [
        "Map endpoints via the endpoint mapper (rpcdump) → services & their dynamic ports",
        "SAMR / LSARPC over rpcclient (null or creds): enumdomusers, RID cycle, group members, lsaquery",
        "Coerce auth: MS-RPRN PrinterBug, MS-EFSR PetitPotam, MS-DFSNM DFSCoerce, Coercer → relay / crack",
        "ZeroLogon (MS-NRPC CVE-2020-1472) → reset the DC machine account → DCSync",
        "Remote exec with creds via Task Scheduler (atexec) or Service Control Manager (scmexec / smbexec)",
        "DRSUAPI → DCSync with replication rights; abuse other interfaces (EVEN6, WKSSVC) as found",
    ],
    "snmp": [
        "Brute community strings with a wordlist (onesixtyone: public, private, community)",
        "snmpwalk the full tree — hostname, users, processes, routes, ARP, listening ports, software",
        "Extended MIBs: running processes with arguments (creds!), installed software, local users",
        "Grab configs/creds: Cisco running-config (1.3.6.1.4.1.9.9.96), SNMPv3 USM users",
        "Writable (RW) community → tamper config, or NET-SNMP EXTEND / EXEC MIB → command execution",
        "SNMPv3 → enumerate & brute usernames / auth (snmpv3-brute)",
    ],
    "ipmi": [
        "Dump BMC password hashes — RAKP auth flaw CVE-2013-4786 (ipmi_dumphashes)",
        "Crack the hashes offline (hashcat mode 7300)",
        "Cipher-0 auth bypass → add/modify a BMC admin, then get to the host console",
        "Default vendor creds (ADMIN/ADMIN, root/calvin on iDRAC)",
    ],
    "dns": [
        "Zone transfer (AXFR) against each nameserver → full record dump",
        "Version query (version.bind CHAOS TXT)",
        "Reverse-lookup the subnet & brute-force subdomains → new hosts/vhosts",
        "Note internal names for /etc/hosts and vhost routing; check dynamic-update/cache-poison",
    ],
    "smtp": [
        "Banner & exact version → searchsploit (Exim CVE-2019-10149, Postfix Shellshock)",
        "Username enumeration via VRFY / EXPN / RCPT TO (smtp-user-enum) → valid AD/local users",
        "Open-relay test → spoof/phish internal users from a trusted-looking sender",
        "Authenticate with reused creds; read internal mail for creds & info",
        "Command injection / template / known MTA RCE → shell as the mail service",
        "Client-side: deliver a malicious attachment / link if a user reads mail",
    ],
    "mail2": [
        "Banner & version (POP3/IMAP) → searchsploit",
        "Authenticate with reused / known creds",
        "Read mailboxes for credentials, tokens and internal information",
    ],
    "telnet": [
        "Banner → identify the device / OS / service",
        "No-auth access or a backdoor prompt?",
        "Default / known creds; careful, targeted brute (lockout-aware)",
        "Sniff cleartext creds if you can MITM the segment",
    ],
    "irc": [
        "Connect; enumerate channels, users and the server software/version",
        "UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) → RCE",
        "searchsploit the ircd; try oper default creds",
    ],
    "rdp": [
        "Check NLA & security layer; grab the machine/domain name (rdp-sec-check / nmap)",
        "Known / weak / reused creds & pass-the-hash (careful with lockout)",
        "BlueKeep CVE-2019-0708 (unpatched 7/2008R2) → RCE",
        "Valid creds → interactive session (xfreerdp; /cert:ignore, drive redirect for transfer)",
        "Post-access: dump creds, enable further access",
    ],
    "vnc": [
        "Connect directly — is there any auth at all?",
        "Weak/short password → crack the VNC challenge-response",
        "Recover stored VNC passwords elsewhere (fixed-key DES) and decrypt",
        "Version CVE (e.g. RealVNC auth bypass) → view / control the desktop",
    ],
    "ssh": [
        "Banner → exact version; searchsploit (libssh CVE-2018-10933 auth bypass, older OpenSSH)",
        "Enumerate valid users (OpenSSH < 7.7 CVE-2018-15473) & list supported auth methods",
        "Reused / known creds & private keys found elsewhere; targeted spray (lockout-aware)",
        "Crack an encrypted private key you recover (ssh2john → hashcat)",
        "After access: pivot — local/remote/dynamic port-forward & tunnelling into internal nets",
        "Restricted shell (rbash / lshell) → escape (ssh -t, command tricks) to a full shell",
        "authorized_keys / SSH-agent abuse for lateral movement & persistence",
        "Weak host key algorithms / Terrapin CVE-2023-48795 — note downgrade risk",
    ],
    "squid": [
        "Use it as a proxy to reach internal hosts & ports (proxychains)",
        "Port-scan / access internal-only services through the proxy",
        "cachemgr info-leak (cache_object://) → internal targets & config",
        "Try creds if the proxy requires auth (reused)",
    ],
    "cups": [
        "Admin web UI on 631/admin; note version",
        "Recent CUPS RCE chain (CVE-2024-47176 …) via a crafted printer/IPP",
        "Enumerate printers & captured jobs; read config for creds",
    ],
    "jetdirect": [
        "PJL / PostScript access (PRET) — filesystem, NVRAM, display",
        "Read/write the printer filesystem; retrieve stored jobs & configs",
        "Extract stored credentials (LDAP/SMB pass-back), captured print jobs",
    ],
    "rservices": [
        "rlogin / rsh / rexec via a trusted host or missing auth",
        "~/.rhosts or /etc/hosts.equiv abuse → log in as root without a password",
    ],
    "x11": [
        "Confirm access is unauthenticated (xdpyinfo / x11-access)",
        "Screenshot the session (xwd); read window contents",
        "Keylog and inject keystrokes to run commands as the logged-in user",
    ],
    "finger": [
        "Enumerate users (finger @IP; finger root@IP) — real names, last login, home",
        "Build a validated user list to feed brute-force / spray on other services",
    ],
    "ident": [
        "Query the owner of each open port (ident-user-enum)",
        "Map services to local user accounts — pick brute-force targets",
    ],
    "rtsp": [
        "Enumerate stream URLs (rtsp-url-brute / Cameradar)",
        "Default / weak camera creds; view the stream",
        "searchsploit the camera/DVR firmware for RCE",
    ],
    "sip": [
        "Enumerate extensions & the PBX (svmap / svwar)",
        "Crack / spray extension passwords (svcrack); register a rogue endpoint",
        "Sniff SIP creds; test toll fraud / call interception",
    ],
    "nntp": [
        "Banner & version → searchsploit",
        "List newsgroups and read articles for info",
        "Try auth / posting; check for an auth bypass",
    ],
    "other": [
        "Grab the banner (nc / telnet / openssl s_client) and identify the service",
        "searchsploit the product & version; check exploit-db / GitHub",
        "Look the port & protocol up in HackTricks for a methodology",
        "Try default / anonymous credentials",
        "Run the protocol's nmap scripts (--script '<name>-*') for quick wins",
        "Interact manually to understand the protocol; note it for deeper research",
    ],
}


def _classify_service(port: int, name, product, version, cpe) -> tuple:
    """Resolve one open port to a service class by the cascade CPE → product/version →
    service name → port default. Returns (label, key, signal) where signal names the
    level that matched (cpe / version / service / port) — a proxy for how much to trust
    it (a port-only guess is far weaker than a CPE/version fingerprint)."""
    sources = (
        ("cpe",     (cpe or "").lower()),
        ("version", f"{product or ''} {version or ''}".lower()),
        ("service", (name or "").lower()),
    )
    for signal, text in sources:
        if not text.strip():
            continue
        for key, label, _ports, tokens in _EXPLOIT_SERVICES:
            if any(tok in text for tok in tokens):
                return label, key, signal
    for key, label, ports, _tokens in _EXPLOIT_SERVICES:
        if port in ports:
            return label, key, "port"
    # unrecognised: still show nmap's own service name if it gave one (so the row is
    # useful for research), else a bare 'other'. Stays keyed 'other' → ranked last, no tool.
    if name:
        return name, _EXPLOIT_UNKNOWN[0], "service"
    return _EXPLOIT_UNKNOWN[1], _EXPLOIT_UNKNOWN[0], "port"


def _exploit_targets(ip: str) -> list:
    """The host's services in exploitation-priority order (no output): a list of
    (port, proto, label, key, ver, signal). Shared by the render and the progress view."""
    services = fetch_services(ip)
    triaged = []
    for port, proto, _state in fetch_ports(ip):
        name, product, version, cpe = services.get((port, proto), (None, None, None, None))
        label, key, signal = _classify_service(port, name, product, version, cpe)
        rank = _EXPLOIT_RANK.get(key, len(_EXPLOIT_SERVICES))
        ver = " ".join(x for x in (product, version) if x)
        triaged.append((rank, port, proto, label, key, ver, signal))
    triaged.sort(key=lambda t: (t[0], t[1]))
    return [(port, proto, label, key, ver, signal)
            for _rank, port, proto, label, key, ver, signal in triaged]


def _service_steps_complete(ip: str, port: int, proto: str, key: str) -> bool:
    """True when every checklist step for this service is resolved (done or skip) — the
    condition for turning the service (and, when all are, phase 6) green."""
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    status = fetch_step_status(ip, port, proto, key)
    return bool(steps) and all(status.get(i) in ("done", "skip")
                               for i in range(1, len(steps) + 1))


def _render_exploit_targets(ip: str) -> list:
    """Numbered, priority-ordered list of the host's services worth attacking (best
    CTF/OSCP candidates first). A service whose whole checklist is resolved shows green.
    Returns the ordered targets so a number can pick one."""
    print(f"\n{BOLD}{ip} — service exploitation{RESET}")
    if not fetch_ports(ip):
        print(f"  {DIM}no open ports recorded — run {BOLD}[1] Port enumeration{RESET}"
              f"{DIM} first{RESET}")
        return []
    targets = _exploit_targets(ip)
    rows = []
    for i, (port, proto, label, key, ver, signal) in enumerate(targets, 1):
        # '?' flags a label not confirmed by a -sV version/CPE fingerprint (a service-name
        # or port guess), so it's clear which rows to verify before trusting them.
        name = label + ("?" if signal in ("service", "port") else "")
        disp = f"{GREEN}{name}{RESET}" if _service_steps_complete(ip, port, proto, key) else name
        rows.append([str(i), disp, f"{port}/{proto}", _cell(ver or "—", 30), f"via {signal}"])
    print(_box_table(["#", "SERVICE", "PORT", "VERSION", "SIGNAL"], rows,
                     aligns=["r", "l", "l", "l", "l"]))
    hostnames = fetch_hostnames(ip)
    if hostnames:
        names = ", ".join(hn for hn, _p, _s in hostnames)
        print(f"  {DIM}hostnames (→ /etc/hosts, vhost-fuzz): {RESET}{CYAN}{names}{RESET}")
    return targets


def _step_parts(step) -> tuple:
    """Normalise a checklist entry to (description, tool_key). A plain string has no
    tool; a (description, tool_key) tuple points at a runner in _STEP_TOOLS."""
    if isinstance(step, tuple):
        return step[0], step[1]
    return step, None


def _tool_http_headers(ip: str, port: int, proto: str) -> str:
    """HTTP step-1 tool: grab a web server's response headers (Server, X-Powered-By,
    cookies) + status, WITHOUT following redirects so a 30x Location (often a vhost) is
    captured. Stdlib only — no external dependency; one focused header grab is enough for
    this step (deeper fingerprinting is step 2 / whatweb)."""
    import urllib.request
    import ssl

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):       # keep the 30x so we see Location
            return None

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    url = f"{'https' if tls else 'http'}://{ip}:{port}/"
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "pshunter"})
    try:
        resp = opener.open(req, timeout=8)
        status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as exc:          # 30x / 4xx / 5xx still carry useful headers
        status, headers = exc.code, exc.headers
    # a connection-level failure (refused / timeout / DNS) propagates → the step won't go green
    lines = [f"{url} → HTTP {status}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    return "\n".join(lines)


# tool key -> (short label shown in the checklist, runner(ip, port, proto) -> output str)
_STEP_TOOLS = {
    "http-headers": ("curl -sI (HTTP headers)", _tool_http_headers),
}

# status glyph + colour for a checklist step
_STEP_MARK = {"done": ("✓", GREEN), "skip": ("⊘", MAGENTA), "running": ("⏳", YELLOW),
              None: ("○", DIM)}


def _render_exploit_checklist(ip: str, target: tuple) -> None:
    """One service's pentest checklist: each step with its status (○ to-do / ✓ done /
    ⊘ skip) and, when one is wired, the tool that can run it."""
    port, proto, label, key, ver, signal = target
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    status = fetch_step_status(ip, port, proto, key)
    print(f"\n{BOLD}{label} — checklist{RESET}  {DIM}{ip}:{port}/{proto}{RESET}")
    if ver:
        print(f"  {DIM}fingerprint:{RESET} {ver} {DIM}(via {signal}){RESET}")
    print()
    for i, step in enumerate(steps, 1):
        desc, tool_key = _step_parts(step)
        st = status.get(i)
        sym, col = _STEP_MARK.get(st, _STEP_MARK[None])
        body = f"{col}{desc}{RESET}" if st in ("done", "skip") else desc   # done → green line
        print(f"  {CYAN}{i:>2}{RESET} {col}{sym}{RESET} {body}")
        if tool_key and tool_key in _STEP_TOOLS:
            print(f"        {DIM}→ {_STEP_TOOLS[tool_key][0]}  ·  run with {BOLD}r {i}{RESET}")


def _step_tool_worker(job: dict, ip: str, port: int, proto: str, tool_key, runner,
                      svc_key: str, step_n: int, prev_status: "str | None") -> None:
    """Background body of a checklist tool: run it, store the output as the port's DETAILS
    (which also extracts hostnames/findings), update the job, and flip the checklist step
    to ✓ done on success — or back to its prior status on error."""
    try:
        out = runner(ip, port, proto)
    except Exception as exc:                              # noqa: BLE001 — never crash the thread
        job["state"], job["error"] = "error", str(exc)
        _job_update(job)
        set_step_status(ip, port, proto, svc_key, step_n, prev_status)   # error → leave as it was
        return
    save_scripts(ip, [{"id": tool_key, "port": port, "proto": proto, "output": out}])
    job["state"], job["output"], job["hosts"] = "done", out, 1
    _job_update(job)
    set_step_status(ip, port, proto, svc_key, step_n, "done")            # success → green


def _run_step_tool(ip: str, target: tuple, n: int) -> None:
    """Launch the wired tool for step n in the background (like the scan phases, so the app
    never blocks); marks the step ⏳ running now, ✓ done when it finishes. Output lands in
    the port's DETAILS / [f] findings, viewable in status."""
    port, proto, _label, key, _ver, _signal = target
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    if not 1 <= n <= len(steps):
        print(f"{RED}✗ no step {n}{RESET}")
        return
    _desc, tool_key = _step_parts(steps[n - 1])
    if not tool_key or tool_key not in _STEP_TOOLS:
        print(f"{DIM}step {n} has no tool — do it manually{RESET}")
        return
    tlabel, runner = _STEP_TOOLS[tool_key]
    prev = fetch_step_status(ip, port, proto, key).get(n)     # so an error can restore it
    set_step_status(ip, port, proto, key, n, "running")       # show ⏳ in the checklist now
    job = _new_job("5", f"{tool_key} · {ip}:{port}", f"{tlabel} on {ip}:{port}/{proto}")
    threading.Thread(target=_step_tool_worker,
                     args=(job, ip, port, proto, tool_key, runner, key, n, prev),
                     daemon=True).start()
    print(f"\n{GREEN}▶ {tlabel} running in the background{RESET} "
          f"{DIM}({ip}:{port}/{proto}) — check {BOLD}[s] status{RESET}{DIM}; output → "
          f"{BOLD}DETAILS{RESET}{DIM} / {BOLD}[f] findings{RESET}")


def _exploit_service_view(ip: str, target: tuple) -> None:
    """One service's checklist: <n> toggles done, s <n> toggles skip, r <n> runs the
    step's tool. Status is saved so progress survives across sessions."""
    port, proto, _label, key = target[0], target[1], target[2], target[3]
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]

    def _toggle(n, want):
        if not 1 <= n <= len(steps):
            print(f"{RED}✗ no step {n}{RESET}")
            return
        cur = fetch_step_status(ip, port, proto, key).get(n)
        set_step_status(ip, port, proto, key, n, None if cur == want else want)

    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v.startswith("s") and v[1:].strip().isdigit():
            _toggle(int(v[1:].strip()), "skip")
            return "refresh"
        if v.startswith("r") and v[1:].strip().isdigit():
            _run_step_tool(ip, target, int(v[1:].strip()))
            return "stay"                        # just the launch line + bare prompt (no redraw)
        if v.isdigit():
            _toggle(int(v), "done")
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> done · s <n> skip · r <n> run · b{RESET}")
        return "stay"

    _run_view(f"{ip}:{port}/{proto} exploit",
              "[Enter] refresh · <n> done · s <n> skip · r <n> run · [b] back · [m] menu",
              lambda: _render_exploit_checklist(ip, target), _handle)


def _exploit_targets_view(ip: str) -> None:
    """Sub-view listing a host's services in exploitation-priority order; a number opens
    that service's pentest checklist."""
    def _handle(targets, v):
        if v == "":
            return "refresh"
        if v.isdigit():
            n = int(v)
            if 1 <= n <= len(targets):
                _exploit_service_view(ip, targets[n - 1])
                return "refresh"
            print(f"{RED}✗ no service {n}{RESET}")
            return "stay"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · enter · b{RESET}")
        return "stay"

    _run_view(f"{ip}/exploit", "[Enter] refresh · <n> select · [b] back · [m] menu",
              lambda: _render_exploit_targets(ip), _handle)


def _handle_service_exploitation() -> None:
    """Phase 6 flow: read a target IP, then show its services (best CTF/OSCP candidates
    first) to pick one to exploit."""
    while True:
        value = _ctx_ask("exploit", "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        if not fetch_ports(ip):
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[1] Port "
                  f"enumeration{RESET}{DIM} first{RESET}")
            continue
        _exploit_targets_view(ip)
        return


# ── OS-family checklists: privilege escalation (6) & persistence (7) ───────────
# Both phases key off the host OS, so they share one engine: pick the OS (when none is on
# record), then work a per-family checklist with toggle/skip status. Selectable OSes are
# the ones that keep showing up on HTB / OSCP / CTF; the 2nd field is the checklist family.
_OS_CHOICES = [
    ("Linux",          "linux"),
    ("Ubuntu",         "linux"),
    ("Debian",         "linux"),
    ("Windows",        "windows"),
    ("Windows Server", "windows"),
    ("Other / Unix",   "linux"),
]

# Privesc checklist per OS family (starter methodology — deeper pass later).
_PRIVESC_STEPS = {
    "linux": [
        "Automated enum (linpeas.sh / LinEnum.sh)",
        "sudo -l — sudo rights → GTFOBins",
        "SUID/SGID binaries (find / -perm -4000) → GTFOBins",
        "Capabilities (getcap -r /) → abuse",
        "Cron jobs & writable scripts / PATH hijack",
        "Writable /etc/passwd, /etc/shadow, service files",
        "Kernel version → known exploit (uname -a; searchsploit)",
        "Interesting files: configs, history, SSH keys, backups, .env",
        "Internal services / ports (ss -tlnp) → local exploit",
        "Password reuse & creds in files / process memory",
    ],
    "windows": [
        "Automated enum (winPEAS.exe / PrivescCheck)",
        "whoami /priv — token privileges (SeImpersonate → Potato)",
        "whoami /groups — group memberships",
        "Services: unquoted paths, weak perms, writable binaries",
        "AlwaysInstallElevated (HKLM + HKCU)",
        "Scheduled tasks & startup items with weak perms",
        "Stored creds: cmdkey, registry, Unattend.xml, SAM/SYSTEM",
        "OS build → known exploit (systeminfo; wesng / Sherlock)",
        "Autologon / SNMP / config files with passwords",
        "Token impersonation / named-pipe → SYSTEM",
    ],
}

# Persistence checklist per OS family (maintain access after a foothold / root).
_PERSIST_STEPS = {
    "linux": [
        "Add an SSH key to ~/.ssh/authorized_keys (root & users)",
        "Cron job — user crontab or /etc/cron.d for a callback",
        "systemd service / timer that re-establishes access",
        "New privileged user / add to sudoers (NOPASSWD)",
        "Shell rc backdoor (.bashrc / .profile / /etc/profile.d)",
        "SUID backdoor binary in a stable path",
        "rc.local / init script on boot",
        "PAM / SSH backdoor; capture creds (PAM, keylogger)",
        "Web shell in a served path (if a web app is present)",
        "Note & stash reusable creds for later re-entry",
    ],
    "windows": [
        "Add a local admin / add user to Administrators",
        "Registry Run keys (HKLM & HKCU …\\CurrentVersion\\Run)",
        "Scheduled task (schtasks) for a callback",
        "New service (sc create) running as SYSTEM",
        "Startup folder shortcut",
        "WMI event subscription (fileless)",
        "Accessibility backdoor (sethc / utilman) at logon screen",
        "Enable RDP + user for interactive re-entry",
        "AD: DCSync / golden / silver ticket (domain persistence)",
        "Dump creds (mimikatz) & pass-the-hash for re-entry",
    ],
}

# Covering-tracks checklist per OS family (authorised-engagement cleanup / anti-forensics).
_COVER_STEPS = {
    "linux": [
        "Clear shell history (~/.bash_history, HISTFILE; unset HISTFILE)",
        "Scrub log entries (auth.log, syslog, wtmp/btmp/lastlog)",
        "Timestomp touched files (touch -r reference / -t)",
        "Remove dropped tools, payloads and temp files",
        "Remove artifacts you added (cron/at, keys, users) when done",
        "Clear/limit auditing (auditd rules, .bash_logout)",
        "Close sessions cleanly; note what was changed for the report",
    ],
    "windows": [
        "Clear PowerShell history (ConsoleHost_history.txt)",
        "Clear event logs (wevtutil cl …) — noisy, note it",
        "Timestomp touched files (SetMACE / PowerShell)",
        "Remove dropped tools, payloads and temp artifacts",
        "Delete Prefetch / Recent / Run-MRU traces",
        "Remove added users, tasks and services when done",
        "Note tampered logging (Sysmon/ETW) for the report",
    ],
}


def _os_family(text: "str | None") -> str:
    """Map an OS string (nmap's guess or the user's pick) to a checklist family."""
    return "windows" if text and "windows" in text.lower() else "linux"


def _select_os(ip: str) -> "tuple | None":
    """Prompt for the host OS and remember the choice. Returns (label, family) or None."""
    print(f"\n{BOLD}Select OS for {ip}{RESET}  {DIM}(pick the target's OS){RESET}")
    for i, (label, _fam) in enumerate(_OS_CHOICES, 1):
        print(f"  {CYAN}{i}{RESET} {label}")
    while True:
        v = _ctx_ask("os", f"<1-{len(_OS_CHOICES)}> · [b] back")
        if v is None or v.lower() in _BACK_WORDS:
            return None
        if v.isdigit() and 1 <= int(v) <= len(_OS_CHOICES):
            label, fam = _OS_CHOICES[int(v) - 1]
            save_os(ip, label)                 # remember it on the host record
            return label, fam
        print(f"{RED}✗ pick 1-{len(_OS_CHOICES)}{RESET}")


def _render_os_checklist(ip: str, kind: str, title: str, steps_map: dict,
                         family: str, os_label: str) -> None:
    """One OS-family checklist (privesc / persistence) for a host, by family."""
    steps = steps_map.get(family, steps_map["linux"])
    status = fetch_step_status(ip, 0, "", f"{kind}:{family}")
    print(f"\n{BOLD}{title} — checklist{RESET}  {DIM}{ip} · {os_label}{RESET}")
    print()
    for i, step in enumerate(steps, 1):
        desc, _tool = _step_parts(step)
        st = status.get(i)
        sym, col = _STEP_MARK.get(st, _STEP_MARK[None])
        body = f"{col}{desc}{RESET}" if st in ("done", "skip") else desc
        print(f"  {CYAN}{i:>2}{RESET} {col}{sym}{RESET} {body}")


def _os_checklist_view(ip: str, kind: str, title: str, steps_map: dict,
                       family: str, os_label: str) -> None:
    """Interactive OS-family checklist: <n> done, s <n> skip, o change OS. Status is saved
    (port 0, service '<kind>:<family>') so it survives across sessions."""
    cur = {"family": family, "label": os_label}        # mutable so [o] can switch it live

    def _toggle(n, want):
        steps = steps_map.get(cur["family"], steps_map["linux"])
        if not 1 <= n <= len(steps):
            print(f"{RED}✗ no step {n}{RESET}")
            return
        svc = f"{kind}:{cur['family']}"
        prev = fetch_step_status(ip, 0, "", svc).get(n)
        set_step_status(ip, 0, "", svc, n, None if prev == want else want)

    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v == "o":
            picked = _select_os(ip)                    # also saves the new OS on the host
            if picked:
                cur["label"], cur["family"] = picked
            return "refresh"
        if v.startswith("s") and v[1:].strip().isdigit():
            _toggle(int(v[1:].strip()), "skip")
            return "refresh"
        if v.isdigit():
            _toggle(int(v), "done")
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> done · s <n> skip · o · b{RESET}")
        return "stay"

    _run_view(f"{ip} {kind}",
              "[Enter] refresh · <n> done · s <n> skip · [o] change OS · [b] back · [m] menu",
              lambda: _render_os_checklist(ip, kind, title, steps_map, cur["family"], cur["label"]),
              _handle)


def _os_checklist_for(ip: str, kind: str, title: str, steps_map: dict) -> None:
    """Open an OS-family checklist for a known host: use the OS on record, or ask for it."""
    os_db = fetch_host_os(ip)
    if os_db:
        _os_checklist_view(ip, kind, title, steps_map, _os_family(os_db), os_db)
        return
    picked = _select_os(ip)
    if picked:
        _os_checklist_view(ip, kind, title, steps_map, picked[1], picked[0])


def _os_checklist_progress(ip: str, kind: str, steps_map: dict) -> tuple:
    """(complete, detail) for an OS-family phase in progress. Not started until an OS is on
    record; complete once every step is resolved (done/skip)."""
    os_db = fetch_host_os(ip)
    if not os_db:
        return False, ""
    family = _os_family(os_db)
    steps = steps_map.get(family, steps_map["linux"])
    status = fetch_step_status(ip, 0, "", f"{kind}:{family}")
    n_done = sum(1 for i in range(1, len(steps) + 1) if status.get(i) in ("done", "skip"))
    return n_done == len(steps), f"{n_done}/{len(steps)} steps · {family}"


def _handle_os_checklist(title: str, kind: str, steps_map: dict) -> None:
    """Menu flow for an OS-family phase: read a target IP, then work its checklist."""
    while True:
        value = _ctx_ask(kind, "<single IP> · [h] help · [b] back · [m] menu")
        if value is None or value.lower() in _BACK_WORDS:
            return
        if value.lower() in _HELP_WORDS:
            print_help()
            continue
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            print(f"{RED}✗ give one valid IP address{RESET}")
            continue
        _os_checklist_for(ip, kind, title, steps_map)
        return


def _handle_privesc() -> None:
    _handle_os_checklist("Privilege Escalation", "privesc", _PRIVESC_STEPS)


def _handle_persist() -> None:
    _handle_os_checklist("Persistence", "persist", _PERSIST_STEPS)


def _handle_cover() -> None:
    _handle_os_checklist("Covering Tracks", "cover", _COVER_STEPS)


# ── placeholder handlers (skeleton — nothing is wired yet) ────────────────────
def _todo(title: str) -> None:
    """Uniform 'not implemented yet' notice for a skeleton screen."""
    print(f"\n{MAGENTA}▸ {title}{RESET}")
    print(f"  {YELLOW}[skeleton]{RESET} {DIM}not wired yet — engine coming soon{RESET}")


def run_phase(key: str) -> None:
    name = _PHASES[key][0]
    _todo(name)


# state -> (colour, label) shown in each status row
_STATE_LABEL = {"running": (YELLOW, "running"), "done": (GREEN, "complete"),
                "error": (RED, "error"), "aborted": (MAGENTA, "aborted")}


def _status_groups(jobs: list) -> list:
    """Group jobs of one phase execution (same run id) into one entry — a phase launches
    its parallel commands together, so they share a number and sit beneath each other.
    Each separate execution keeps its own number, even for the same phase re-run."""
    groups: list = []
    index: dict = {}                      # run id -> its group, to keep runs distinct
    for j in jobs:
        run = j.get("run") or f"job{id(j)}"
        if run in index:
            index[run].append(j)
        else:
            g = [j]
            index[run] = g
            groups.append(g)
    return groups


def show_status() -> list:
    """Command history, grouped by phase: each entry shows its number, the phase name,
    the combined state (running/complete/error/aborted) and a short found yes/no; the
    phase's command(s) sit beneath it. Returns the ordered groups so the caller can
    stop / view one by number."""
    with _JOBS_LOCK:
        jobs = list(_JOBS)
    print(f"\n{BOLD}Status{RESET}")
    if not jobs:
        print(f"  {DIM}no commands have run yet{RESET}")
        return []
    groups = _status_groups(jobs)
    for n, g in enumerate(groups, 1):
        title = _PHASES.get(g[0]["phase"], (g[0]["name"],))[0]
        state = _agg_state([j["state"] for j in g])
        colour, text = _STATE_LABEL.get(state, (DIM, state))
        found = f"{GREEN}yes{RESET}" if any(j["hosts"] > 0 for j in g) else f"{DIM}no{RESET}"
        multi = len(g) > 1
        tail = f"  {DIM}·{RESET} {DIM}{len(g)} cmds{RESET}" if multi else ""
        print(f"  {CYAN}{n}{RESET} {BOLD}{title}{RESET}  "
              f"{DIM}·{RESET} {colour}{text}{RESET}  {DIM}·{RESET} found: {found}{tail}")
        for j in g:
            if multi:                                    # per-command state so a partly
                jc, jt = _STATE_LABEL.get(j["state"], (DIM, j["state"]))   # done phase is clear
                print(f"       {jc}{jt:<8}{RESET} {DIM}{j['command']}{RESET}")
            else:
                print(f"       {DIM}{j['command']}{RESET}")
            if j["error"]:
                print(f"       {RED}{j['error']}{RESET}")
    return groups


def _cell(value: "str | None", width: int) -> str:
    """Fit a value into a fixed-width column: '—' when missing, truncated with '…'
    when longer than ``width`` so long vendor/OS/hostname strings can't break the
    table layout."""
    s = value if value else "—"
    return s if len(s) <= width else s[:width - 1] + "…"


def _vwidth(s: str) -> int:
    """Visible width of a string — ANSI colour codes don't count."""
    return len(re.sub(r"\x1b\[[0-9;]*m", "", s))


def _box_table(headers: list, rows: list, aligns: "list | None" = None,
               indent: str = "  ") -> str:
    """Render a box-drawing table. Cells may contain ANSI colour codes — column widths
    and padding use the visible width so the borders stay aligned. ``aligns`` is 'l'/'r'
    per column (default left)."""
    n = len(headers)
    aligns = aligns or ["l"] * n
    w = [_vwidth(h) for h in headers]
    for r in rows:
        for i in range(n):
            w[i] = max(w[i], _vwidth(r[i]) if i < len(r) else 0)

    def pad(s, i):
        gap = " " * max(0, w[i] - _vwidth(s))
        return gap + s if aligns[i] == "r" else s + gap

    bar = f"{DIM}│{RESET}"

    def rule(left, mid, right):
        return f"{indent}{DIM}{left}" + mid.join("─" * (w[i] + 2) for i in range(n)) + f"{right}{RESET}"

    out = [rule("┌", "┬", "┐"),
           indent + bar + bar.join(f" {BOLD}{pad(headers[i], i)}{RESET} " for i in range(n)) + bar,
           rule("├", "┼", "┤")]
    for r in rows:
        out.append(indent + bar + bar.join(f" {pad(r[i] if i < len(r) else '', i)} " for i in range(n)) + bar)
    out.append(rule("└", "┴", "┘"))
    return "\n".join(out)


def show_database() -> list:
    """Discovered hosts: IP / MAC / vendor / OS / hostname where known. Long values
    are truncated so the table stays aligned. Returns the ordered rows so the caller
    can delete one by its number."""
    rows = fetch_hosts()
    print(f"\n{BOLD}Database — hosts{RESET}")
    if not rows:
        print(f"  {DIM}empty — no hosts discovered yet{RESET}")
        return rows
    trows = [[str(i), ip or "—", _cell(mac, 17), _cell(vendor, 16), _cell(os_, 20),
              _cell(hostname, 24), str(nports) if nports else "—"]
             for i, (ip, mac, vendor, hostname, os_, nports) in enumerate(rows, 1)]
    print(_box_table(["#", "IP", "MAC", "VENDOR", "OS", "HOSTNAME", "PORTS"], trows,
                     aligns=["r", "l", "l", "l", "l", "l", "r"]))
    return rows


def _delete_host(rows: list, n: int) -> None:
    """Remove one host (by its list number) and everything tied to it — ports, services,
    scripts, vulns and its command-history jobs — from the database."""
    if not 1 <= n <= len(rows):
        print(f"{RED}✗ no host {n}{RESET}")
        return
    ip = rows[n - 1][0]
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for table in ("hosts", "ports", "services", "scripts", "vulns", "exploit_steps", "hostnames"):
                conn.execute(f"DELETE FROM {table} WHERE ip = ?", (ip,))
            conn.commit()
        finally:
            conn.close()
    # also drop this host's command history: jobs that name the IP as a whole token
    # (subnet-discovery jobs don't match, so a shared scope scan is left intact).
    pat = re.compile(r"(?<!\d)" + re.escape(ip) + r"(?!\d)")
    with _JOBS_LOCK:
        gone = [j for j in _JOBS
                if pat.search(j.get("command") or "") or pat.search(j.get("name") or "")]
        gone_ids = {id(j) for j in gone}
        for j in gone:
            if j["state"] == "running":
                j["cancel"].set()             # stop any in-flight scan for this host
        _JOBS[:] = [j for j in _JOBS if id(j) not in gone_ids]
        for j in _JOBS:                       # discovery jobs must forget this host too,
            j["found"].discard(ip)            # or progress would still credit phase 1
    ids = [(j["db_id"],) for j in gone if j.get("db_id") is not None]
    if ids:
        with _DB_LOCK:
            conn = _db_connect()
            try:
                conn.executemany("DELETE FROM jobs WHERE id = ?", ids)
                conn.commit()
            finally:
                conn.close()
    tail = f" {DIM}(+{len(gone)} history entr{'y' if len(gone) == 1 else 'ies'}){RESET}" if gone else ""
    print(f"{GREEN}✓ removed {ip}{RESET}{tail}")


def _render_host_ports(ip: str) -> list:
    """Print one host's numbered open ports / protocol / state / service / version
    (plus its OS when detected). Returns the ordered ports so the caller can open a
    port's NSE (-sC) output by number."""
    ports = fetch_ports(ip)
    services = fetch_services(ip)
    os_ = fetch_host_os(ip)
    head = f"\n{BOLD}{ip} — ports{RESET}"
    if os_:
        head += f"  {DIM}· OS:{RESET} {os_}"
    print(head)
    if not ports:
        print(f"  {DIM}none{RESET}")
        return ports
    vulns = fetch_vulns(ip)
    flagged = {(v[0], v[1]) for v in vulns}          # (port, proto) with a finding
    scripted = fetch_scripted_ports(ip)              # (port, proto) that have script output
    trows = []
    for i, (port, proto, state) in enumerate(ports, 1):
        name, product, version, _cpe = services.get((port, proto), (None, None, None, None))
        ver = " ".join(x for x in (product, version) if x) or "—"
        verlen = 48 if (port, proto) in flagged else 28   # ports with findings show fuller VERSION
        more = "›" if (port, proto) in scripted else "—"  # is there more to see for this port?
        trows.append([str(i), str(port), proto, state or "—",
                      _cell(name, 15), _cell(ver, verlen), more])
    print(_box_table(["#", "PORT", "PROTO", "STATE", "SERVICE", "VERSION", "MORE"], trows,
                     aligns=["r", "r", "l", "l", "l", "l", "l"]))
    return ports


def _render_host_findings(ip: str) -> None:
    """The host's findings, opened with [f]: short one-line summaries — the FINDINGS list
    (incl. phase-4 vuln and phase-6 tool results) and the aggregated CVE list — plus the
    raw host-level NSE output (HOST FINDINGS). Per-port tool output lives in each port's
    DETAILS view, not here."""
    vulns = fetch_vulns(ip)
    host_scripts = fetch_scripts(ip, 0, "")
    hostnames = fetch_hostnames(ip)
    # short summaries: everything except the CVE-lookup rows (those get their own section)
    findings = [v for v in vulns if v[3] != "CVE"]
    cve_map = {}                                     # CVE → set of "port/proto" it was seen on
    for port, proto, _script, _state, cve, _risk, _summary in vulns:
        for c in (cve or "").split(","):
            c = c.strip()
            if c:
                cve_map.setdefault(c, set()).add(f"{port}/{proto}")

    print(f"\n{BOLD}{ip} — findings{RESET}")
    if not findings and not cve_map and not host_scripts and not hostnames:
        print(f"  {DIM}none{RESET}")
        return
    if hostnames:
        print(f"\n  {BOLD}HOSTNAMES{RESET}  {DIM}(add to /etc/hosts → vhost-fuzz){RESET}")
        for hn, _port, source in hostnames:
            print(f"    {CYAN}{hn}{RESET}  {DIM}{source}{RESET}")
    if findings:
        print(f"\n  {BOLD}FINDINGS{RESET}")
        for port, proto, script, state, cve, risk, summary in findings:
            col = RED if state in ("VULNERABLE", "LIKELY") else \
                (YELLOW if state == "EXPOSED" else DIM)
            print(f"    {col}{state:<11}{RESET}{port}/{proto:<5}"
                  f"{_cell(summary or script, 60)}")
    if cve_map:
        kev = _load_kev()
        ordered = sorted(cve_map, key=_cve_sort_key)     # newest first
        kev_hits = [c for c in ordered if c in kev]
        rest = [c for c in ordered if c not in kev]
        print(f"\n  {BOLD}CVE{RESET}")

        def _group(title, cves, col):
            print(f"    {title}")
            if cves:
                for c in cves:
                    print(f"      {col}{c}{RESET}  {DIM}{', '.join(sorted(cve_map[c]))}{RESET}")
            else:
                print(f"      {DIM}none{RESET}")

        _group(f"{BOLD}⚑ KEV CVE — known exploited{RESET}", kev_hits, RED)   # header neutral, CVEs red
        _group(f"{BOLD}other CVE{RESET}", rest, DIM)                          # rest → grey
    if host_scripts:
        print(f"\n  {BOLD}HOST FINDINGS{RESET}")
        for script, output in host_scripts:
            print(f"    {CYAN}{script}{RESET}")
            for line in (output or "").strip().split("\n"):
                print(f"        {line.rstrip()}")


def _render_port_scripts(ip: str, port: int, proto: str) -> None:
    """Print the full collected output for one port — every tool's raw result: service
    detection (-sC), the vuln scan (phase 4) and service exploitation (phase 6). The short
    one-line takeaways are summarised separately in [f] findings, not repeated here."""
    rows = fetch_scripts(ip, port, proto)          # all tools' output stored for this port
    print(f"\n{BOLD}{ip}:{port}/{proto} — DETAILS{RESET}")
    if not rows:
        print(f"  {DIM}None{RESET}")
        return
    for script, output in rows:
        print(f"  {CYAN}{script}{RESET}")
        for line in (output or "").strip().split("\n"):
            print(f"      {line.rstrip()}")


def _port_scripts_view(ip: str, ports: list, n: int) -> None:
    """Sub-view for one port's -sC output: stays open (the ports table is NOT redrawn)
    until the user goes back."""
    if not 1 <= n <= len(ports):
        print(f"{RED}✗ no port {n}{RESET}")
        return
    port, proto, _state = ports[n - 1]

    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v == "f":
            _host_findings_view(ip)
            return "refresh"
        if v == "p":
            _open_host_progress(ip)
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— f · p · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}:{port}/{proto}",
              "[Enter] refresh · [f] findings · [p] progress · [b] back · [m] menu",
              lambda: _render_port_scripts(ip, port, proto), _handle)


def _host_findings_view(ip: str) -> None:
    """Sub-view for one host's findings, opened with [f]; [p] jumps to its progress. Stays
    open (the ports table is NOT redrawn) until the user goes back."""
    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v == "p":
            _open_host_progress(ip)
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— p · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}/findings", "[Enter] refresh · [p] progress · [b] back · [m] menu",
              lambda: _render_host_findings(ip), _handle)


def _host_ports_view(rows: list, n: int) -> None:
    """Sub-view for one host's ports: stays open (the host list is NOT redrawn) until the
    user goes back. A port number opens its -sC output; [f]/[p] jump to findings/progress."""
    if not 1 <= n <= len(rows):
        print(f"{RED}✗ no host {n}{RESET}")
        return
    ip = rows[n - 1][0]

    def _handle(ports, v):
        if v == "":
            return "refresh"
        if v.lower() == "f":
            _host_findings_view(ip)
            return "refresh"
        if v.lower() == "p":
            _open_host_progress(ip)
            return "refresh"
        if v.isdigit():
            n = int(v)
            if 1 <= n <= len(ports):
                _port_scripts_view(ip, ports, n)
                return "refresh"
            print(f"{RED}✗ no port {n}{RESET}")     # bad number → bare re-prompt, no redraw
            return "stay"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · f · p · b · enter{RESET}")
        return "stay"

    _run_view(ip, "[Enter] refresh · <n> select · [f] findings · [p] progress · [b] back · [m] menu",
              lambda: _render_host_ports(ip), _handle)


def clear_database() -> None:
    """Wipe all discovered hosts (and their ports/services) after confirmation."""
    if not os.path.exists(DB_PATH):
        print(f"\n{DIM}database already empty{RESET}")
        return
    ans = _ask("clear ALL discovered hosts (+ ports/services)? [y/N]:")
    if ans is None or ans.lower() != "y":
        print(f"{DIM}cancelled{RESET}")
        return
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for table in ("hosts", "ports", "services", "scripts", "vulns", "exploit_steps", "hostnames"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
        finally:
            conn.close()
    print(f"{GREEN}✓ database cleared{RESET}")


def new_session() -> None:
    """Start a fresh session: abort any running scan and wipe the whole database —
    discovered hosts and the command history alike."""
    if not os.path.exists(DB_PATH) and not _JOBS:
        print(f"\n{DIM}already a clean session{RESET}")
        return
    ans = _ask("start a NEW session — wipe ALL data (hosts + history)? [y/N]:")
    if ans is None or ans.lower() != "y":
        print(f"{DIM}cancelled{RESET}")
        return
    with _JOBS_LOCK:
        for j in _JOBS:                   # stop anything still running
            if j["state"] == "running":
                j["cancel"].set()
        _JOBS.clear()
    if os.path.exists(DB_PATH):
        with _DB_LOCK:
            conn = _db_connect()
            try:
                for table in ("hosts", "jobs", "ports", "services", "scripts", "vulns",
                              "exploit_steps", "hostnames"):
                    conn.execute(f"DELETE FROM {table}")
                conn.commit()
            finally:
                conn.close()
    print(f"{GREEN}✓ new session — database cleared{RESET}")


def _upgrade_to_root() -> None:
    """Re-launch pshunter under sudo so SYN/UDP scans get raw-socket privileges. sudo
    itself handles the password (we never see it); progress lives in the DB, so the
    fresh root instance reloads everything. If the password prompt is cancelled we stay
    in the current (unprivileged) session."""
    if _is_root():
        print(f"\n{GREEN}already running as root{RESET}")
        return
    if not shutil.which("sudo"):
        print(f"\n{RED}✗ sudo not found — start it yourself with: sudo pshunter{RESET}")
        return
    running = any(j["state"] == "running" for j in _JOBS)
    note = " (running scans will restart)" if running else ""
    print(f"\n{BOLD}Upgrade to root{RESET}{DIM} — enter your sudo password when asked; "
          f"progress is saved in the database{note}.{RESET}")
    try:
        rc = subprocess.call(["sudo", "-v"])          # prompts on the tty, caches creds
    except OSError as exc:
        print(f"{RED}✗ could not run sudo: {exc}{RESET}")
        return
    if rc != 0:
        print(f"{DIM}upgrade cancelled — still running as a normal user{RESET}")
        return
    # Credentials cached: replace this process with a root one (no second prompt). Keep
    # PURRSH_TERM_ID so the in-app report spawn keeps working after the upgrade.
    print(f"{GREEN}▶ re-launching as root…{RESET}")
    sys.stdout.flush()
    script = os.path.abspath(__file__)
    try:
        os.execvp("sudo", ["sudo", "-n", "--preserve-env=PURRSH_TERM_ID",
                           sys.executable, script])
    except OSError as exc:
        print(f"{RED}✗ re-launch failed: {exc}{RESET}")


def _stop_job(groups: list, n: int) -> None:
    """Signal a running phase (by its status number) to abort — every still-running
    command in the group is killed within a tick; whatever each found so far is kept."""
    if not 1 <= n <= len(groups):
        print(f"{RED}✗ no scan {n}{RESET}")
        return
    grp = groups[n - 1]
    running = [j for j in grp if j["state"] == "running"]
    if not running:
        print(f"{DIM}{n} already {_agg_state([j['state'] for j in grp])}{RESET}")
        return
    for j in running:
        j["cancel"].set()
    print(f"{YELLOW}aborting {n}…{RESET}")


# External terminal emulators tried, in order, for the standalone spawn. The second
# item is the argv that precedes the program to run inside them ("-e" for most,
# "--" for gnome-terminal, "-x" for xfce4-terminal, nothing for kitty).
_TERM_EMULATORS = [
    ("x-terminal-emulator", ["-e"]), ("qterminal", ["-e"]), ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]), ("gnome-terminal", ["--"]), ("tilix", ["-e"]),
    ("alacritty", ["-e"]), ("kitty", []), ("xterm", ["-e"]),
]


def _render_report_session(command: str, output: "str | None") -> str:
    """Build the coloured replay text: stock-Kali prompt (frame green/non-bold,
    user㉿host and $ bold-blue, ~ white) + greenish first command word (rest plain)
    + plain output. Kept in sync with the host app's in-tab renderer so both spawn
    paths look identical."""
    E = "\033"
    # cmd1 is the turquoise from QTermWidget's "Linux" scheme (Color6 = 24,178,178),
    # as 24-bit truecolor so the shade is stable across themes.
    grn, bblu, cmd1, wht, rs = (f"{E}[32m", f"{E}[1;34m", f"{E}[38;2;24;178;178m",
                                f"{E}[1;37m", f"{E}[0m")
    import getpass
    import socket
    try:
        user, host = getpass.getuser(), socket.gethostname()
    except Exception:
        user, host = "kali", "kali"
    first, _, rest = command.partition(" ")
    cmd = f"{cmd1}{first}{rs}" + (f" {rest}" if rest else "")
    prompt = (f"{grn}┌──({bblu}{user}㉿{host}{rs}{grn})-[{wht}~{rs}{grn}]{rs}\n"
              f"{grn}└─{bblu}${rs} {cmd}")
    return f"{prompt}\n{output or '(no output captured)'}\n"


def _spawn_report_in_app(job_id: int) -> None:
    """In-app path: emit an OSC 777 marker carrying only the job id. The PurrSh3ll
    host app parses it, reads the command/output from pshunter.db itself and opens
    a QTermWidget tab — so a scanned host cannot forge a command into this channel."""
    sys.stdout.write(f"\033]777;psspawn;{int(job_id)}\007")
    sys.stdout.flush()


def _spawn_report_standalone(job: dict) -> None:
    """Standalone path: render the replay ourselves and open it in an external
    terminal emulator (self-deleting temp file). Falls back to printing inline in the
    current terminal when there is no display or no emulator (e.g. over SSH)."""
    session = _render_report_session(job.get("command", ""), job.get("output"))
    term = next(((shutil.which(b), flag) for b, flag in _TERM_EMULATORS if shutil.which(b)),
                (None, None))
    have_display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if not have_display or not term[0]:
        print()                                   # headless fallback: show it here
        sys.stdout.write(session)
        sys.stdout.flush()
        return
    binary, flag = term
    fd, path = tempfile.mkstemp(prefix="pshunter_report_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(session)
        q = shlex.quote(path)
        script = f"clear; cat {q}; rm -f {q}; exec ${{SHELL:-/bin/bash}}"
        subprocess.Popen([binary] + flag + ["sh", "-c", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
        print(f"{GREEN}opened scan output in a new terminal window{RESET}")
    except Exception as exc:
        _safe_unlink(path)
        print(f"{RED}✗ could not open a terminal: {exc}{RESET}")


def _view_command(groups: list, n: int) -> None:
    """Show phase n's command(s) + output in a spawned terminal (variant B) — via the
    PurrSh3ll host app when running inside it, or an external terminal standalone. A phase
    with several commands opens one terminal per finished command."""
    if not 1 <= n <= len(groups):
        print(f"{RED}✗ no scan {n}{RESET}")
        return
    viewable = [j for j in groups[n - 1]
                if j.get("db_id") is not None and j["state"] != "running"]
    if not viewable:
        print(f"{DIM}scan {n} — no captured output yet{RESET}")
        return
    if os.environ.get("PURRSH_TERM_ID"):
        for j in viewable:
            _spawn_report_in_app(j["db_id"])
        note = f" ({len(viewable)} cmds)" if len(viewable) > 1 else ""
        print(f"{GREEN}opened scan {n} output{note} in a new terminal{RESET}")
    else:
        for j in viewable:
            _spawn_report_standalone(j)


def _clear_status() -> None:
    """Drop finished commands from the history (in memory and in the DB); running
    scans are kept so they can still be watched or stopped."""
    with _JOBS_LOCK:
        kept = [j for j in _JOBS if j["state"] == "running"]
        removed = [j for j in _JOBS if j["state"] != "running"]
        _JOBS[:] = kept
    ids = [(j["db_id"],) for j in removed if j.get("db_id") is not None]
    if ids:
        with _DB_LOCK:
            conn = _db_connect()
            try:
                conn.executemany("DELETE FROM jobs WHERE id = ?", ids)
                conn.commit()
            finally:
                conn.close()
    print(f"{GREEN}✓ cleared {len(removed)} finished command(s){RESET}")


# ── action views (stay open until the user goes back) ─────────────────────────
def _run_view(module: str, options: str, render, handle=None) -> None:
    """Keep an interactive screen open. ``render()`` draws the content and may return a
    context passed to ``handle``. ``handle(ctx, v)`` returns 'refresh' to redraw the
    screen or 'stay' to just re-prompt WITHOUT redrawing — so an invalid option / typo
    doesn't reprint the whole view, only the bare prompt shows again. b / back / /exit
    leave. The options hint shows on the first prompt after a redraw, then bare."""
    first = True
    while True:
        if not first:
            _hr()
        first = False
        ctx = render()
        with_opts = True
        while True:
            v = _ctx_ask(module, options if with_opts else "")
            with_opts = False
            if v is None or v.lower() in _BACK_WORDS:
                return
            action = handle(ctx, v.strip().lower()) if handle else "stay"
            if action == "refresh":
                break                             # redraw the screen
            # 'stay' → re-prompt (bare), screen not redrawn


def _view(render, module: str, options: str = "[b] back") -> None:
    """Static screen (e.g. help): drawn once, kept open until the user goes back."""
    _run_view(module, options, render)


def _status_view() -> None:
    """Status screen: refresh, view a scan's command + output in a spawned terminal
    (``v <n>``), stop a running scan (``stop <n>``), or clear finished history."""
    def _handle(jobs, v):
        if v == "":
            return "refresh"
        if v == "c":
            _clear_status()
            return "refresh"
        if v.startswith("stop"):
            rest = v[len("stop"):].strip()
            if rest.isdigit():
                _stop_job(jobs, int(rest))
                return "refresh"
            print(f"{RED}✗ use: stop <n>{RESET}")
            return "stay"
        if v.startswith("v"):
            rest = v[1:].strip()
            if rest.isdigit():
                _view_command(jobs, int(rest))
            else:
                print(f"{RED}✗ use: v <n>{RESET}")
            return "stay"
        if v.isdigit():
            _stop_job(jobs, int(v))
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— v <n> · stop <n> · c · b · enter{RESET}")
        return "stay"

    _run_view("status", "[Enter] refresh · v <n> view · stop <n> abort · [c] clear · [b] back",
              show_status, _handle)


def _database_view() -> None:
    """Database screen: host list; type a host number to see its ports/services,
    ``r <n>`` to remove a host, ``c`` to clear, ``b`` to go back."""
    def _handle(rows, v):
        if v == "":
            return "refresh"
        if v == "c":
            clear_database()
            return "refresh"
        if v.startswith("r"):
            rest = v[1:].strip()
            if rest.isdigit():
                _delete_host(rows, int(rest))
                return "refresh"
            print(f"{RED}✗ use: r <n>{RESET}")
            return "stay"
        if v.isdigit():
            _host_ports_view(rows, int(v))
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · r <n> · c · b · enter{RESET}")
        return "stay"

    _run_view("database",
              "[Enter] refresh · <n> select · r <n> remove · [c] clear · [b] back",
              show_database, _handle)


# ── main loop ─────────────────────────────────────────────────────────────────
def main() -> int:
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print_help()      # `pshunter -h/--help` (also used by `pshelp pshunter`)
        return 0
    print_header()
    if os.path.exists(DB_PATH):        # apply any pending schema migrations up front
        with _DB_LOCK:
            _db_connect().close()      # (so raw reads like fetch_hosts see new columns)
    _load_jobs()          # restore the saved command history
    try:
        while True:
            print_menu()
            while True:                       # prompt loop: a typo re-prompts bare, the
                try:                          # menu is only reprinted after a real action
                    choice = input(f"{BOLD}{CYAN}[menu]{RESET}{DIM} ›{RESET} ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{DIM}bye.{RESET}")
                    return 0

                if choice in ("/exit", "\\exit", "exit", "q", "quit"):
                    print(f"{DIM}bye.{RESET}")
                    return 0
                try:
                    if choice in _HELP_WORDS:
                        _view(print_help, "help")
                    elif choice == "0":
                        _handle_host_discovery()
                    elif choice == "1":
                        _handle_port_enum()
                    elif choice == "2":
                        _handle_service_detection()
                    elif choice == "3":
                        _handle_vuln_scan()
                    elif choice == "4":
                        _handle_cve_lookup()
                    elif choice == "5":
                        _handle_service_exploitation()
                    elif choice == "6":
                        _handle_privesc()
                    elif choice == "7":
                        _handle_persist()
                    elif choice == "8":
                        _handle_cover()
                    elif choice in _PHASES:
                        run_phase(choice)
                    elif choice in ("s", "status"):
                        _status_view()
                    elif choice in ("d", "database"):
                        _database_view()
                    elif choice in ("n", "new"):
                        new_session()
                    elif choice in ("u", "upgrade") and not _is_root():
                        _upgrade_to_root()
                    elif choice in _MENU_WORDS:
                        pass                  # already at the menu → just redraw it
                    else:
                        print(f"{RED}✗ pick 0-8, s, d, n, h or /exit{RESET}")
                        continue              # invalid → bare re-prompt, menu not reprinted
                except _ToMenu:               # m/menu typed inside a sub-view → back here
                    pass
                break                         # a valid action ran → redraw the menu

            print(f"{DIM}{'─' * 56}{RESET}\n")
    except _ExitApp:          # /exit typed at any sub-prompt
        print(f"\n{DIM}bye.{RESET}")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
