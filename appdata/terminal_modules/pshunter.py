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

import ftplib
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
APP_VERSION = "0.1.0-skeleton"


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
              f"{DIM}; SYN/UDP scans need root — press {RESET}{YELLOW}[u]{RESET}{DIM} upgrade{RESET}")
    else:
        print(f"{GREEN}  ● root — full scan capability (raw sockets){RESET}")
    print()


# ── phases (the offensive kill-chain, in order) ───────────────────────────────
# Each entry: (menu key, name, one-line intent). The order is the recommended
# progression; nothing forces it, but later phases build on earlier findings.
PHASES = [
    ("1", "Host discovery",      "find which hosts are alive on the target scope"),
    ("2", "Port enumeration",    "map open TCP/UDP ports on a live host"),
    ("3", "Service detection",   "fingerprint the service/version behind each port"),
    ("4", "Vuln scan",           "run vulnerability checks against detected services"),
    ("5", "CVE lookup",          "match service CPEs to known CVEs"),
    ("6", "Service exploitation", "attempt exploitation / access on a chosen service"),
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
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[2] Port "
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
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[2] Port "
                  f"enumeration{RESET}{DIM} (and {BOLD}[3] Service detection{RESET}{DIM}) first{RESET}")
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
    services, scripts = [], []
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
    return {"ip": ip, "services": services, "scripts": scripts, "os": os_name}


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
    output      TEXT
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
            conn.commit()
        finally:
            conn.close()
    return len(rows)


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


def save_exploit_output(ip: str, port: int, proto: str, script: str, output: str,
                        state: str, risk: "str | None", summary: str) -> None:
    """Persist a phase-6 tool's raw output (scripts table — shown in the port's DETAILS)
    and a one-line finding (vulns — shown in [f] findings), keyed by (ip, port, proto,
    script) so re-running a tool just refreshes its result."""
    if not ip or _is_self_ip(ip):
        return
    now = datetime.now().isoformat(timespec="seconds")
    with _DB_LOCK:
        conn = _db_connect()
        try:
            conn.execute(
                "INSERT INTO scripts (ip, port, proto, script, output, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(ip, port, proto, script) DO UPDATE SET "
                "  output = excluded.output, last_seen = excluded.last_seen",
                (ip, port, proto, script, output, now, now))
            conn.execute(
                "INSERT INTO vulns (ip, port, proto, script, state, cve, risk, summary, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(ip, port, proto, script) DO UPDATE SET "
                "  state = excluded.state, cve = excluded.cve, risk = excluded.risk, "
                "  summary = excluded.summary, last_seen = excluded.last_seen",
                (ip, port, proto, script, state, None, risk, summary, now, now))
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
                "INSERT INTO jobs (created, phase, name, command, state, hosts, error, output) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (job["created"], job["phase"], job["name"], job["command"],
                 job["state"], job["hosts"], job["error"], job["output"]))
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
                            "error, output FROM jobs ORDER BY id").fetchall()
    except sqlite3.OperationalError:      # jobs table not created yet
        return
    finally:
        conn.close()
    corrected = []
    with _JOBS_LOCK:
        _JOBS.clear()
        for jid, created, phase, name, command, state, hosts, error, output in rows:
            st = "aborted" if state == "running" else state
            job = {"db_id": jid, "created": created, "phase": phase, "name": name,
                   "command": command, "state": st, "hosts": hosts or 0,
                   "found": set(), "error": error, "output": output,
                   "cancel": threading.Event()}
            _JOBS.append(job)
            if st != state:
                corrected.append(job)
    for job in corrected:                 # write back the running->aborted fix
        _job_update(job)


def _new_job(phase: str, name: str, command: str) -> dict:
    job = {
        "phase": phase, "name": name, "command": command,
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
    name = _PHASES["1"][0]
    threads = []
    for args in (_DISCOVERY_FAST, _DISCOVERY_SLOW):
        command = " ".join(["nmap"] + args + targets)
        job = _new_job("1", name, command)
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
    name = _PHASES["2"][0]
    threads = []
    for _label, args in _port_scan_specs():
        command = " ".join(["nmap"] + args + [ip])
        job = _new_job("2", name, command)
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
                save_scripts(h["ip"], scr)
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
    name = _PHASES["3"][0]
    threads = []
    for _label, args in _service_scan_specs(ip):
        command = " ".join(["nmap"] + args + [ip])
        job = _new_job("3", name, command)
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
    name = _PHASES["4"][0]
    families = _vuln_families(ip)
    if not families:
        job = _new_job("4", name, f"nmap (no known services on {ip})")
        job["state"] = "done"
        _job_update(job)
        return
    threads = []
    for label, scripts, ports in families:
        command = f"nmap -sV --script {scripts} -T3 -p {','.join(str(p) for p in ports)} {ip}"
        job = _new_job("4", f"{name} · {label}", command)
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
    name = _PHASES["5"][0]
    job = _new_job("5", f"{name} · {ip}", f"cve-index lookup (offline NVD) for {ip}")
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
              f"(run {BOLD}[3] Service detection{RESET}{DIM} first, or no known CVEs){RESET}")
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
            print(f"{DIM}note: no services recorded for {ip} — run {BOLD}[3] Service "
                  f"detection{RESET}{DIM} first{RESET}")
            continue
        _do_cve_lookup(ip)
        return


# ── progress (per-host workflow tracker) ──────────────────────────────────────
def _host_job_states(ip: str) -> dict:
    """Latest command-history state per phase for one host. A job belongs to the host
    when the IP appears as a whole token in its command or name; later jobs overwrite
    earlier ones, so the freshest state per phase is returned (running/done/…)."""
    pat = re.compile(r"(?<!\d)" + re.escape(ip) + r"(?!\d)")
    states = {}
    with _JOBS_LOCK:
        jobs = list(_JOBS)
    for j in jobs:
        if pat.search(j.get("command") or "") or pat.search(j.get("name") or ""):
            states[j["phase"]] = j["state"]      # chronological order → last one wins
    return states


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
        disc = [j for j in _JOBS if j["phase"] == "1"]
        discovered = any(ip in j["found"] for j in disc)
        live_discovery = any(j["found"] for j in disc)
    phase1_done = discovered or (known and not live_discovery)

    # phase key -> (has evidence in the DB, short detail line)
    evidence = {
        "1": (phase1_done, "on record" if phase1_done else ""),
        "2": (bool(ports), f"{len(ports)} open port(s)" if ports else ""),
        "3": (bool(fingerprinted) or bool(host_scripts) or bool(scripted),
              f"{len(fingerprinted)} fingerprinted" if fingerprinted else ("NSE output" if (host_scripts or scripted) else "")),
        "4": (bool(vuln_findings), f"{len(vuln_findings)} vuln finding(s)" if vuln_findings else ""),
        "5": (bool(cve_findings), f"{n_cve} CVE" if cve_findings else ""),
        "6": (False, ""),                                    # skeleton — not wired yet
    }

    print(f"\n{BOLD}{ip} — progress{RESET}")
    if not known and not ports and not vulns and not jobstate:
        print(f"  {DIM}nothing recorded for this host yet — run {BOLD}[1] Host discovery{RESET}"
              f"{DIM} / {BOLD}[2] Port enumeration{RESET}{DIM} first{RESET}")
        return

    done = 0
    for key, name, _desc in PHASES:
        has, detail = evidence[key]
        st = jobstate.get(key)
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
    if key == "1":
        print(f"{DIM}note: host discovery scans a subnet/range, not one host — use "
              f"{BOLD}[1]{RESET}{DIM} from the menu{RESET}")
        return
    if key == "6":
        _exploit_targets_view(ip)                            # service triage (skeleton)
        return
    if key == "5":
        if not os.path.exists(CVE_INDEX_PATH):
            print(f"\n{YELLOW}⚠ CVE index not found{RESET} {DIM}({os.path.basename(CVE_INDEX_PATH)}) "
                  f"— build it with the installer's NVD step, then retry{RESET}")
            return
        if not fetch_services(ip):
            print(f"{DIM}note: no services recorded for {ip} — run {BOLD}[3] Service "
                  f"detection{RESET}{DIM} first{RESET}")
            return
        _do_cve_lookup(ip)
        return
    # phases 2–4: background nmap scans on a time budget
    if key == "3" and not fetch_ports(ip):
        print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[2] Port "
              f"enumeration{RESET}{DIM} first (OS scan still runs if root){RESET}")
    if key == "4" and not fetch_ports(ip):
        print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[2] Port "
              f"enumeration{RESET}{DIM} (and {BOLD}[3] Service detection{RESET}{DIM}) first{RESET}")
        return
    name = _PHASES[key][0]
    if key == "4":
        print(f"{DIM}vuln + auth scripting{RESET}")
    module = {"2": "ports", "3": "service", "4": "vuln"}[key]
    minutes = _prompt_minutes(module, name, ip)
    if minutes is None:
        return
    if key == "2":
        _start_port_enum(ip, minutes)
        detail = "fast + full TCP + UDP"
    elif key == "3":
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
    ("rsync",   "rsync",              {873}, ("rsync",)),
    ("redis",   "Redis",              {6379, 6380}, ("redis",)),
    ("memcached", "Memcached",        {11211}, ("memcache",)),
    ("elastic", "Elasticsearch",      {9200, 9300}, ("elasticsearch", "elastic")),
    ("mongodb", "MongoDB",            {27017, 27018}, ("mongodb", "mongod", "mongo")),
    ("couchdb", "CouchDB",            {5984, 6984}, ("couchdb",)),
    ("amqp",    "AMQP / RabbitMQ",    {5672}, ("amqp", "rabbitmq")),
    ("docker",  "Docker API",         {2375, 2376}, ("docker",)),
    ("rmi",     "Java RMI",           {1050, 1098, 1099}, ("rmi", "jrmi")),
    ("ajp",     "AJP / Tomcat (Ghostcat)", {8009}, ("ajp13", "ajp")),
    ("svn",     "SVN (svnserve)",     {3690}, ("svn", "subversion")),
    ("mysql",   "MySQL / MariaDB",    {3306}, ("mysql", "mariadb")),
    ("mssql",   "MS SQL Server",      {1433, 1434}, ("ms-sql", "mssql", "microsoft sql")),
    ("psql",    "PostgreSQL",         {5432}, ("postgresql", "postgres")),
    ("oracle",  "Oracle DB",          {1521, 1748, 1754, 1808, 1809, 2100},
     ("oracle", "tns")),
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
    ("rservices", "BSD r-services",   {512, 513, 514}, ("rlogin", "rexec", "rsh", "rshd")),
    ("x11",     "X11",                {6000, 6001, 6002, 6003, 6004, 6005}, ("x11",)),
    ("finger",  "Finger",             {79}, ("finger",)),
    ("rtsp",    "RTSP (cameras)",     {554, 8554}, ("rtsp",)),
    ("sip",     "SIP / VoIP",         {5060, 5061}, ("sip",)),
    ("nntp",    "NNTP",               {119}, ("nntp",)),
]
_EXPLOIT_RANK = {key: i for i, (key, *_rest) in enumerate(_EXPLOIT_SERVICES)}
_EXPLOIT_UNKNOWN = ("other", "other / unknown")   # fallback bucket, always ranked last


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
    return _EXPLOIT_UNKNOWN[1], _EXPLOIT_UNKNOWN[0], "port"


def _render_exploit_targets(ip: str) -> list:
    """Numbered, priority-ordered list of the host's services worth attacking (best
    CTF/OSCP candidates first). Returns the ordered targets so a number can pick one."""
    ports = fetch_ports(ip)
    services = fetch_services(ip)
    print(f"\n{BOLD}{ip} — service exploitation{RESET}")
    if not ports:
        print(f"  {DIM}no open ports recorded — run {BOLD}[2] Port enumeration{RESET}"
              f"{DIM} first{RESET}")
        return []
    triaged = []
    for port, proto, _state in ports:
        name, product, version, cpe = services.get((port, proto), (None, None, None, None))
        label, key, signal = _classify_service(port, name, product, version, cpe)
        rank = _EXPLOIT_RANK.get(key, len(_EXPLOIT_SERVICES))
        ver = " ".join(x for x in (product, version) if x)
        triaged.append((rank, port, proto, label, key, ver, signal))
    triaged.sort(key=lambda t: (t[0], t[1]))
    ordered, rows = [], []
    for i, (_rank, port, proto, label, key, ver, signal) in enumerate(triaged, 1):
        ordered.append((port, proto, label, key, ver, signal))
        rows.append([str(i), label, f"{port}/{proto}", _cell(ver or "—", 30), f"via {signal}"])
    print(_box_table(["#", "SERVICE", "PORT", "VERSION", "SIGNAL"], rows,
                     aligns=["r", "l", "l", "l", "l"]))
    return ordered


def _tool_ftp_anon(ip: str, port: int) -> tuple:
    """Check FTP anonymous login with ftplib (offline, no external tool). Returns
    (state, risk, summary, output); state None means the check couldn't run."""
    lines = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=8)
        banner = (ftp.getwelcome() or "").strip()
        if banner:
            lines.append(banner)
        ftp.login()                                      # defaults to anonymous:anonymous
        lines.append("login anonymous:anonymous → ACCEPTED")
        try:
            listing = []
            ftp.retrlines("LIST", listing.append)
            if listing:
                lines.append("directory listing:")
                lines.extend("  " + row for row in listing[:50])
                if len(listing) > 50:
                    lines.append(f"  … (+{len(listing) - 50} more)")
            else:
                lines.append("directory listing: (empty)")
        except ftplib.all_errors as exc:
            lines.append(f"listing failed: {exc}")
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()
        return "EXPOSED", "MEDIUM", "Anonymous FTP login allowed", "\n".join(lines)
    except ftplib.error_perm as exc:
        lines.append(f"login anonymous:anonymous → REJECTED ({exc})")
        return "INFO", None, "Anonymous FTP login rejected", "\n".join(lines)
    except ftplib.all_errors as exc:
        return None, None, None, f"connection failed: {exc}"


def _tool_whatweb(ip: str, port: int, proto: str) -> tuple:
    """Fingerprint a web service with whatweb. Returns (state, risk, summary, output);
    state None means whatweb is missing or produced nothing."""
    if not shutil.which("whatweb"):
        return None, None, None, "whatweb not installed — apt install whatweb"
    name = (fetch_services(ip).get((port, proto)) or (None,))[0] or ""
    tls = port in (443, 8443) or "https" in name.lower() or "ssl" in name.lower()
    url = f"{'https' if tls else 'http'}://{ip}:{port}"
    try:
        proc = subprocess.run(["whatweb", "--color=never", "-a", "1", url],
                              capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        return None, None, None, "whatweb timed out"
    except Exception as exc:                             # noqa: BLE001 — surface any launch error
        return None, None, None, f"whatweb failed: {exc}"
    out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    if not out:
        return None, None, None, "whatweb returned no output"
    first = out.splitlines()[0]
    return "INFO", None, f"whatweb: {first}", out


# service class -> (script name, runner) for the tools wired so far
_EXPLOIT_TOOLS = {
    "ftp":  ("ftp-anon", lambda ip, port, proto: _tool_ftp_anon(ip, port)),
    "http": ("whatweb",  lambda ip, port, proto: _tool_whatweb(ip, port, proto)),
}


def _exploit_worker(job: dict, ip: str, port: int, proto: str, script: str, runner) -> None:
    """Background body of an exploit: run the tool, store its output as a finding, and
    update the job. Any result/error is read back from [s] status and [f] findings."""
    try:
        state, risk, summary, output = runner(ip, port, proto)
    except Exception as exc:                             # noqa: BLE001 — never crash the thread
        job["state"], job["error"] = "error", str(exc)
        _job_update(job)
        return
    if state is None:                                    # tool couldn't run / no result
        job["state"], job["output"] = "done", output
        _job_update(job)
        return
    save_exploit_output(ip, port, proto, script, output, state, risk, summary)
    job["state"], job["hosts"], job["output"] = "done", 1, output
    _job_update(job)


def _run_exploit(ip: str, target: tuple) -> None:
    """Launch the wired tool for a chosen service (FTP anon / HTTP whatweb) in the
    background; its output is saved to [f] findings. Not-yet-wired services show a
    skeleton notice instead."""
    port, proto, label, key, ver, signal = target
    tool = _EXPLOIT_TOOLS.get(key)
    if not tool:
        print(f"\n{MAGENTA}▸ exploit — {label}{RESET}  {DIM}{ip}:{port}/{proto}{RESET}")
        if ver:
            print(f"  {DIM}fingerprint:{RESET} {ver}  {DIM}(via {signal}){RESET}")
        print(f"  {YELLOW}[skeleton]{RESET} {DIM}tooling for '{key}' not wired yet — coming soon{RESET}")
        return
    script, runner = tool
    job = _new_job("6", f"{_PHASES['6'][0]} · {ip}:{port} {script}",
                   f"{script} on {ip}:{port}/{proto}")
    threading.Thread(target=_exploit_worker, args=(job, ip, port, proto, script, runner),
                     daemon=True).start()
    print(f"\n{GREEN}▶ {label} exploit running in the background{RESET} "
          f"{DIM}({ip}:{port}/{proto} · {script}) — check {BOLD}[s] status{RESET}{DIM} "
          f"or {BOLD}[f] findings{RESET}")


def _exploit_targets_view(ip: str) -> None:
    """Sub-view listing a host's services in exploitation-priority order; a number runs the
    wired tool for that service (or shows a skeleton for the not-yet-wired ones)."""
    def _handle(targets, v):
        if v == "":
            return "refresh"
        if v.isdigit():
            n = int(v)
            if 1 <= n <= len(targets):
                _run_exploit(ip, targets[n - 1])
                return "stay"
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
            print(f"{DIM}note: no open ports recorded for {ip} — run {BOLD}[2] Port "
                  f"enumeration{RESET}{DIM} first{RESET}")
            continue
        _exploit_targets_view(ip)
        return


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


def show_status() -> list:
    """Command history: each row shows its number, the phase name, the command's
    state (running/complete/error/aborted) and a short found yes/no; the command
    sits below. Returns the ordered jobs so the caller can stop one by number."""
    with _JOBS_LOCK:
        jobs = list(_JOBS)
    print(f"\n{BOLD}Status{RESET}")
    if not jobs:
        print(f"  {DIM}no commands have run yet{RESET}")
        return jobs
    for n, j in enumerate(jobs, 1):
        colour, text = _STATE_LABEL.get(j["state"], (DIM, j["state"]))
        found = f"{GREEN}yes{RESET}" if j["hosts"] > 0 else f"{DIM}no{RESET}"
        print(f"  {CYAN}{n}{RESET} {BOLD}{j['name']}{RESET}  "
              f"{DIM}·{RESET} {colour}{text}{RESET}  {DIM}·{RESET} found: {found}")
        print(f"       {DIM}{j['command']}{RESET}")
        if j["error"]:
            print(f"       {RED}{j['error']}{RESET}")
    return jobs


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
            for table in ("hosts", "ports", "services", "scripts", "vulns"):
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
    # short summaries: everything except the CVE-lookup rows (those get their own section)
    findings = [v for v in vulns if v[3] != "CVE"]
    cve_map = {}                                     # CVE → set of "port/proto" it was seen on
    for port, proto, _script, _state, cve, _risk, _summary in vulns:
        for c in (cve or "").split(","):
            c = c.strip()
            if c:
                cve_map.setdefault(c, set()).add(f"{port}/{proto}")

    print(f"\n{BOLD}{ip} — findings{RESET}")
    if not findings and not cve_map and not host_scripts:
        print(f"  {DIM}none{RESET}")
        return
    if findings:
        print(f"\n  {BOLD}FINDINGS{RESET}")
        for port, proto, script, state, cve, risk, summary in findings:
            col = RED if state in ("VULNERABLE", "LIKELY") else \
                (YELLOW if state == "EXPOSED" else DIM)
            print(f"    {col}{state:<11}{RESET}{port}/{proto:<5}"
                  f"{_cell(summary or script, 60)}")
    if cve_map:
        print(f"\n  {BOLD}CVE{RESET}")
        for c in sorted(cve_map, key=_cve_sort_key):     # newest first
            where = ", ".join(sorted(cve_map[c]))
            print(f"    {RED}{c}{RESET}  {DIM}{where}{RESET}")
        print(f"    {DIM}hint: narrowed to closer version matches — if none fit, "
              f"start from the newest CVE above{RESET}")
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
            _port_scripts_view(ip, ports, int(v))
            return "refresh"
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
            for table in ("hosts", "ports", "services", "scripts", "vulns"):
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
                for table in ("hosts", "jobs", "ports", "services", "scripts", "vulns"):
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


def _stop_job(jobs: list, n: int) -> None:
    """Signal a running scan (by its status number) to abort — nmap is killed within
    a tick, whatever it found so far is kept, and the row turns to 'aborted'."""
    if not 1 <= n <= len(jobs):
        print(f"{RED}✗ no scan {n}{RESET}")
        return
    job = jobs[n - 1]
    if job["state"] != "running":
        print(f"{DIM}{n} already {job['state']}{RESET}")
        return
    job["cancel"].set()
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


def _view_command(jobs: list, n: int) -> None:
    """Show scan n's command + output in a spawned terminal (variant B) — via the
    PurrSh3ll host app when running inside it, or an external terminal standalone."""
    if not 1 <= n <= len(jobs):
        print(f"{RED}✗ no scan {n}{RESET}")
        return
    job = jobs[n - 1]
    if job.get("db_id") is None:
        print(f"{RED}✗ scan {n} was not saved{RESET}")
        return
    if job["state"] == "running":
        print(f"{DIM}scan {n} still running — no captured output yet{RESET}")
        return
    if os.environ.get("PURRSH_TERM_ID"):
        _spawn_report_in_app(job["db_id"])
        print(f"{GREEN}opened scan {n} output in a new terminal{RESET}")
    else:
        _spawn_report_standalone(job)


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
                    elif choice == "1":
                        _handle_host_discovery()
                    elif choice == "2":
                        _handle_port_enum()
                    elif choice == "3":
                        _handle_service_detection()
                    elif choice == "4":
                        _handle_vuln_scan()
                    elif choice == "5":
                        _handle_cve_lookup()
                    elif choice == "6":
                        _handle_service_exploitation()
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
                        print(f"{RED}✗ pick 1-6, s, d, n, h or /exit{RESET}")
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
