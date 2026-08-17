#!/usr/bin/env python3
# PurrSh3ll — purragent run-mode gate (which tool calls need the user's OK)
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Pure, side-effect-free policy extracted from purragent so it can be unit-tested
# in isolation: given the run mode and a resolved tool call, decide whether to ask
# the user before running it.
#
#   plan      → tools are never offered (handled upstream; not seen here).
#   auto      → run everything without asking.
#   confirm   → ask before every tool call.
#   semi-auto → ask only for risky actions, decided by a deterministic, fail-closed
#     classifier: read-only tools/commands run automatically; anything that changes
#     local state — or that we can't positively classify as read-only — asks.

import json
import os
import re
import shlex

import mcp_client   # for split_namespaced; dependency-free, no import cycle

# The built-in tools server (appdata/mcp_servers/hacktools_server.py). Its tools
# are the only ones whose behaviour we know, so the semi-auto read-only allowlist
# applies ONLY to them — a third-party MCP server's tool that happens to share a
# name (e.g. its own "read_file") must not inherit the "safe" verdict.
BUILTIN_TOOLS_SERVER = "hacktools"

# Tools that only read/inspect — safe to run unattended in semi-auto.
READONLY_TOOLS = {"read_file", "list_dir", "grep", "find_files"}

# Base commands that only read/inspect the system (recon included). Anything NOT
# here makes run_command ask — the allowlist fails closed, so we never need to
# enumerate every dangerous command.
READONLY_BINS = {
    "cd", "pushd", "popd", "true", "false", "test", "sleep", "seq",
    "ls", "dir", "cat", "head", "tail", "less", "more", "stat", "file", "wc",
    "sort", "uniq", "cut", "tr", "column", "tac", "nl", "fold", "rev",
    "grep", "egrep", "fgrep", "rg", "ag", "find", "locate", "which", "whereis",
    "type", "tree", "readlink", "realpath", "basename", "dirname",
    "echo", "printf", "pwd", "date", "cal", "uptime", "uname", "hostname",
    "whoami", "id", "groups", "who", "w", "last", "lscpu", "lsblk", "lsusb",
    "lspci", "env", "printenv", "du", "df", "free", "ps", "pstree", "top",
    "lsof", "vmstat", "ss", "netstat", "ip", "ifconfig", "route", "arp",
    "dig", "nslookup", "host", "whois", "ping", "traceroute", "tracepath",
    "mtr", "curl", "wget", "nmap", "masscan", "nc", "ncat", "netcat",
    "awk", "sed", "xxd", "hexdump", "od", "strings", "base64", "base32",
    "md5sum", "sha1sum", "sha256sum", "cksum", "git", "jq", "yq",
    "nikto", "whatweb", "gobuster", "feroxbuster", "dirb", "dirsearch", "ffuf",
    "wpscan", "enum4linux", "smbclient", "smbmap", "dnsrecon", "dnsenum",
    "sslscan", "sslyze", "testssl.sh", "nuclei", "httpx", "subfinder", "amass",
}

# High-signal dangerous constructs → confirm with a clear reason (the allowlist
# would already flag most of these, but an explicit reason is better UX).
DANGER_PATTERNS = [
    (re.compile(r'(^|[\s;&|(])(sudo|doas|su)([\s;&|)]|$)'), "runs with elevated privileges (sudo)"),
    (re.compile(r'(^|[\s;&|(])(rm|rmdir|shred|unlink)([\s;&|)]|$)'), "deletes files"),
    (re.compile(r'(^|[\s;&|(])(dd|mkfs\S*|fdisk|parted|wipefs|blkdiscard|sgdisk)([\s;&|)]|$)'), "writes to disks/partitions"),
    (re.compile(r'(^|[\s;&|(])(mv|cp|ln|tee|truncate|touch|install|rsync)([\s;&|)]|$)'), "creates/moves/overwrites files"),
    (re.compile(r'(^|[\s;&|(])(chmod|chown|chgrp)([\s;&|)]|$)'), "changes permissions/ownership"),
    (re.compile(r'(^|[\s;&|(])(kill|pkill|killall)([\s;&|)]|$)'), "kills processes"),
    (re.compile(r'(^|[\s;&|(])(systemctl|service|initctl|rc-service)([\s;&|)]|$)'), "controls system services"),
    (re.compile(r'(^|[\s;&|(])(apt|apt-get|aptitude|dpkg|pip|pip3|pipx|npm|gem|snap|flatpak|pacman|yum|dnf|brew)([\s;&|)]|$)'), "changes installed packages"),
    (re.compile(r'(^|[\s;&|(])(mount|umount|swapon|swapoff)([\s;&|)]|$)'), "changes mounts"),
    (re.compile(r'(^|[\s;&|(])(reboot|shutdown|halt|poweroff|init|telinit)([\s;&|)]|$)'), "reboots or powers off the host"),
    (re.compile(r'(^|[\s;&|(])(useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd|adduser|deluser)([\s;&|)]|$)'), "modifies users/groups"),
    (re.compile(r'(^|[\s;&|(])(iptables|ip6tables|nft|ufw|firewall-cmd)([\s;&|)]|$)'), "changes firewall rules"),
    (re.compile(r'(^|[\s;&|(])(crontab|at)([\s;&|)]|$)'), "schedules jobs"),
    (re.compile(r':\s*\(\s*\)\s*\{.*[|&].*\}'), "looks like a fork bomb"),
    (re.compile(r'\|\s*(sudo\s+)?(sh|bash|zsh|dash|python\d?|perl|ruby)\b'), "pipes output into an interpreter"),
]


def has_write_redirect(cmd: str) -> bool:
    """True if the command redirects output into a file (not /dev/null or an fd
    dup like 2>&1) — i.e. it writes somewhere."""
    for m in re.finditer(r'\d*>>?', cmd):
        rest = cmd[m.end():].lstrip()
        if rest[:1] == "&" or rest.startswith("/dev/null"):
            continue
        return True
    return False


def classify_command(command: str):
    """(needs_confirm, reason) for a run_command shell string in semi-auto."""
    cmd = command.strip()
    if not cmd:
        return False, ""
    for pat, why in DANGER_PATTERNS:
        if pat.search(cmd):
            return True, why
    if has_write_redirect(cmd):
        return True, "redirects output into a file"
    bins = []
    for seg in re.split(r'[;&|]+', cmd):
        seg = seg.strip()
        if not seg:
            continue
        try:
            toks = shlex.split(seg)
        except ValueError:
            return True, "command could not be parsed safely"
        if toks:
            bins.append(os.path.basename(toks[0]))
    if bins and all(b in READONLY_BINS for b in bins):
        return False, ""
    unknown = next((b for b in bins if b not in READONLY_BINS), cmd[:30])
    return True, f"not a known read-only command ({unknown})"


def needs_confirm(mode: str, name: str, args: dict):
    """(confirm?, reason) for a resolved tool call under the given run mode."""
    if mode == "auto":
        return False, ""
    if mode == "confirm":
        return True, ""
    if mode != "semi-auto":
        return False, ""
    server, tool = mcp_client.split_namespaced(name)
    # The read-only / command classifier only understands the built-in hacktools
    # server's tools. Anything from a third-party MCP server is unknown → ask, even
    # if its tool name collides with a built-in one (e.g. another "read_file").
    if server != BUILTIN_TOOLS_SERVER:
        return True, "external MCP tool — behaviour unknown"   # fail-closed
    if tool in READONLY_TOOLS:
        return False, ""
    if tool == "run_command":
        return classify_command(str(args.get("command", "")))
    if tool == "http_request":
        method = str(args.get("method", "GET")).upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return False, ""
        return True, f"{method} request may change server state"
    if tool in ("write_file", "edit_file"):
        return True, "modifies a file on disk"
    return True, "unclassified tool"                  # fail-closed


def approval_key(name: str, args: dict) -> str:
    """Identity of a tool call for the 'always allow' memory: the full namespaced
    tool name PLUS its exact arguments. So 'always' remembers this SPECIFIC call
    (e.g. this exact command), not the whole tool — a different command through the
    same tool still asks."""
    try:
        blob = json.dumps(args, sort_keys=True, ensure_ascii=False)
    except Exception:                                  # noqa: BLE001
        blob = str(args)
    return f"{name}\x00{blob}"
