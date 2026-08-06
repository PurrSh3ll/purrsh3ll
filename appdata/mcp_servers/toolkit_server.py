#!/usr/bin/env python3
# PurrSh3ll — toolkit MCP server
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# A dependency-free Model Context Protocol server (JSON-RPC 2.0 over stdio) that
# gives purragent a small, practical toolset for authorized pentesting and
# security research on the local host:
#
#   run_command  — run a shell command, capture stdout/stderr/exit code
#   read_file    — read a text file (optionally a line range)
#   write_file   — create / overwrite / append a file
#   edit_file    — replace a string inside a file (search/replace)
#   list_dir     — list a directory (name, type, size)
#   grep         — regex-search file contents under a path
#   http_request — make an HTTP request and return status/headers/body
#
# Same wire protocol as demo_server.py, so any MCP client talks to it unchanged.
# Paths are resolved relative to the process working directory (the MCP client
# launches this with cwd set to the project root).
#
# SECURITY: run_command / write_file / edit_file are powerful. This server does
# not sandbox or gate them — that is the agent's job (purragent's confirm /
# semi-auto modes). It only enforces timeouts and output-size caps so a single
# call can't hang the agent or flood the model's context.

import fnmatch
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone  # noqa: F401  (available for future tools)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "purrtools"
SERVER_VERSION = "0.1.0"

MAX_OUTPUT = 20000          # chars: cap on any single tool's returned text
# Fixed per-call cap. The model cannot override these — no tool exposes a
# `timeout` argument — so every call is bounded the same way (and matches the
# client's 30s transport cap in mcp_client.MCPServer).
DEFAULT_CMD_TIMEOUT = 30    # seconds
DEFAULT_HTTP_TIMEOUT = 120  # seconds (web/API calls can legitimately be slow)
MAX_GREP_HITS = 200


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated, {len(text) - limit} more chars]"


def _resolve(path: str) -> str:
    """Expand $VARS and a leading ~ so paths like ~/Desktop/x or $HOME/x — which
    models commonly emit — land where the user expects (open() would not)."""
    return os.path.expanduser(os.path.expandvars(path))


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
def _tool_run_command(args):
    command = args.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("`command` must be a non-empty string")
    timeout = DEFAULT_CMD_TIMEOUT          # fixed; not model-controllable
    workdir = args.get("workdir") or None
    if workdir:
        workdir = _resolve(workdir)
        if not os.path.isdir(workdir):
            raise ValueError(f"workdir not found: {workdir}")
    try:
        proc = subprocess.run(
            command, shell=True, cwd=workdir, capture_output=True,
            text=True, timeout=float(timeout),
            # Isolate the child's stdin from the server's — otherwise a command
            # that reads stdin (cat, ssh, a prompt…) would consume the JSON-RPC
            # channel and break the MCP transport.
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return f"exit code: (timeout after {timeout}s)\ncommand: {command}"
    out = proc.stdout or ""
    err = proc.stderr or ""
    parts = [f"exit code: {proc.returncode}"]
    if out.strip():
        parts.append("--- stdout ---\n" + out.rstrip("\n"))
    if err.strip():
        parts.append("--- stderr ---\n" + err.rstrip("\n"))
    if not out.strip() and not err.strip():
        parts.append("(no output)")
    return _truncate("\n".join(parts))


def _tool_read_file(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    path = _resolve(path)
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    offset = int(args.get("offset", 0) or 0)      # 0-based starting line
    limit = args.get("limit")                     # number of lines (None = all)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        raise ValueError(f"could not read file: {e}")
    if offset:
        lines = lines[offset:]
    if limit is not None:
        lines = lines[:int(limit)]
    body = "".join(lines)
    header = f"{path} ({os.path.getsize(path)} bytes)\n"
    return _truncate(header + body)


def _tool_write_file(args):
    path = args.get("path")
    content = args.get("content", "")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    if not isinstance(content, str):
        raise ValueError("`content` must be a string")
    path = _resolve(path)
    append = bool(args.get("append", False))
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)
    verb = "appended to" if append else "wrote"
    return f"{verb} {path} ({len(content)} chars)"


def _tool_edit_file(args):
    path = args.get("path")
    old = args.get("old_string")
    new = args.get("new_string", "")
    if not isinstance(path, str) or not path:
        raise ValueError("`path` must be a string")
    if not isinstance(old, str) or old == "":
        raise ValueError("`old_string` must be a non-empty string")
    if not isinstance(new, str):
        raise ValueError("`new_string` must be a string")
    path = _resolve(path)
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    replace_all = bool(args.get("replace_all", False))
    with open(path, encoding="utf-8") as f:
        data = f.read()
    count = data.count(old)
    if count == 0:
        raise ValueError("old_string not found in file")
    if count > 1 and not replace_all:
        raise ValueError(f"old_string is not unique ({count} matches); pass "
                         "replace_all=true or give more surrounding context")
    data = data.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return f"edited {path} ({count} replacement{'s' if count != 1 else ''})"


def _tool_list_dir(args):
    path = _resolve(args.get("path", ".") or ".")
    if not os.path.isdir(path):
        raise ValueError(f"not a directory: {path}")
    rows = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        try:
            if os.path.isdir(full):
                rows.append(f"  [dir]  {name}/")
            else:
                rows.append(f"  {os.path.getsize(full):>10}  {name}")
        except OSError:
            rows.append(f"  [?]    {name}")
    header = f"{os.path.abspath(path)}  ({len(rows)} entries)"
    return _truncate("\n".join([header] + rows))


def _tool_grep(args):
    pattern = args.get("pattern")
    if not isinstance(pattern, str) or pattern == "":
        raise ValueError("`pattern` must be a non-empty string")
    path = _resolve(args.get("path", ".") or ".")
    flags = re.IGNORECASE if args.get("ignore_case") else 0
    globpat = args.get("glob")
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"invalid regex: {e}")

    hits = []
    targets = []
    if os.path.isfile(path):
        targets = [path]
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv")]
            for fn in files:
                if globpat and not fnmatch.fnmatch(fn, globpat):
                    continue
                targets.append(os.path.join(root, fn))

    for fpath in targets:
        try:
            with open(fpath, encoding="utf-8", errors="strict") as f:
                for i, line in enumerate(f, 1):
                    if rx.search(line):
                        hits.append(f"{fpath}:{i}: {line.rstrip()}")
                        if len(hits) >= MAX_GREP_HITS:
                            hits.append(f"… [stopped at {MAX_GREP_HITS} matches]")
                            return _truncate("\n".join(hits))
        except (UnicodeDecodeError, OSError):
            continue   # skip binary / unreadable files
    return _truncate("\n".join(hits) if hits else "(no matches)")


def _tool_find_files(args):
    pattern = args.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("`pattern` must be a non-empty string")
    path = _resolve(args.get("path", ".") or ".")
    if not os.path.isdir(path):
        raise ValueError(f"not a directory: {path}")
    limit = int(args.get("max_results", 200) or 200)
    ignore_case = bool(args.get("ignore_case"))
    pat = pattern.lower() if ignore_case else pattern
    hits = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv")]
        for fn in files:
            name = fn.lower() if ignore_case else fn
            if fnmatch.fnmatchcase(name, pat):
                hits.append(os.path.join(root, fn))
                if len(hits) >= limit:
                    hits.append(f"… [stopped at {limit} matches]")
                    return _truncate("\n".join(hits))
    return _truncate("\n".join(hits) if hits else "(no matches)")


def _tool_http_request(args):
    url = args.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("`url` must be a string")
    method = (args.get("method") or "GET").upper()
    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
    body = args.get("body")
    timeout = float(DEFAULT_HTTP_TIMEOUT)  # fixed; not model-controllable
    data = body.encode() if isinstance(body, str) else None

    # Default to a browser-like User-Agent — many sites (e.g. Wikimedia) reject
    # urllib's default "Python-urllib/x.y" with 403. Caller can override it.
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = "Mozilla/5.0"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_headers = dict(resp.getheaders())
            payload = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers or {})
        payload = e.read().decode("utf-8", errors="replace") if e.fp else ""
    except Exception as e:
        raise ValueError(f"request failed: {e}")

    hdr_lines = "\n".join(f"  {k}: {v}" for k, v in resp_headers.items())
    return _truncate(f"{method} {url}\nstatus: {status}\n"
                     f"--- headers ---\n{hdr_lines}\n--- body ---\n{payload}")


# Each tool carries THREE descriptions, for a three-stage tool-selection design:
#
#   short  — a one-line "what it does". Cheap enough that the client can send the
#            whole catalog of these to the model so it knows what capabilities
#            exist (grounding), without paying for full schemas.
#   normal — the model-facing description used when the tool is actually offered
#            for execution (this is the classic MCP `description`; parameters go
#            with it via inputSchema).
#   long   — a rich, keyword- and scenario-heavy description NOT meant for the
#            model directly. The client indexes it in a vector DB (RAG) and, when
#            the model describes the tool it needs in natural language, retrieves
#            the best-matching tools by semantic similarity against these. Written
#            to overlap with how a model would phrase a need (synonyms, use cases,
#            CLI names) so retrieval recall stays high.
#
# Each tool also carries `examples`: a handful of natural-language requests the
# tool satisfies. Matching a model's short phrasing against these example queries
# (query-to-query) tends to retrieve better than matching it against long prose,
# so the client can index them alongside (or instead of) the long description.
#
# name -> (handler, short, normal, long, examples, inputSchema)
TOOLS = {
    "run_command": (
        _tool_run_command,
        # short
        "Run a shell command on the local host and capture its output.",
        # normal
        "Run a shell command on the local host and return its exit code, stdout "
        "and stderr. Use for recon/tools (nmap, curl, git…) and anything not "
        "covered by the file tools. Each call runs in a fresh shell — `cd` does "
        "not carry over between calls, so pass `workdir`, use absolute paths, or "
        "chain commands with `&&`.",
        # long
        "Executes an arbitrary shell command on the local machine through the "
        "system shell and returns the exit code together with captured stdout and "
        "stderr. This is the general-purpose escape hatch for anything the "
        "dedicated file and web tools do not cover: running command-line security "
        "and reconnaissance tools (nmap, masscan, nikto, gobuster, ffuf, dirb, "
        "whatweb, sqlmap, hydra, netcat/nc, dig, whois, ping, traceroute), "
        "inspecting the system (ps, ss, netstat, ip, ifconfig, id, whoami, uname, "
        "env, systemctl), managing packages or services, running git, and piping "
        "or chaining several commands together. Reach for it whenever the task is "
        "phrased as run, execute, launch, invoke, call, shell out, use the "
        "terminal, run a scan, or names a specific CLI program. Supports an "
        "optional working directory; every call is capped at a fixed 30-second "
        "timeout so a long-running or hung command cannot block the agent. Not the "
        "right tool for reading or writing "
        "files as data — prefer read_file and write_file for that. Keywords: "
        "shell, bash, sh, terminal, command line, execute, run program, "
        "subprocess, CLI tool, scan, recon, system command.",
        # examples
        [
            "run an nmap scan against a host",
            "execute a shell command in the terminal",
            "check which ports are open on a machine",
            "run a git command",
            "launch gobuster to brute-force directories",
            "show the running processes on the system",
            "use a command-line tool that has no dedicated tool here",
        ],
        {
            "type": "object",
            "properties": {
                "command": {"type": "string",
                            "description": "The shell command to run."},
                "workdir": {"type": "string",
                            "description": "Directory to run in (default: current)."},
            },
            "required": ["command"],
        },
    ),
    "read_file": (
        _tool_read_file,
        # short
        "Read the contents of a text file.",
        # normal
        "Read a text file. Optionally start at line `offset` and read `limit` "
        "lines (for large files).",
        # long
        "Opens a text file on disk and returns its contents, optionally limited to "
        "a range of lines via a starting offset and a line limit so large files "
        "can be read a page at a time. Use it whenever the task involves looking "
        "at, viewing, opening, inspecting, displaying, printing or cat-ing an "
        "existing file — configuration files, logs, source code, wordlists, scan "
        "output saved to disk, notes, files under /etc, or any UTF-8/text "
        "document. Prefer it over running cat/head/tail/less through the shell "
        "because it handles encoding, paging and output-size caps cleanly. Not for "
        "listing a directory (use list_dir) nor for searching many files for a "
        "pattern (use grep). Keywords: open file, view file, cat, read, show "
        "contents, inspect file, print file, load file, head, tail, display file.",
        # examples
        [
            "read the contents of a configuration file",
            "show me what is inside /etc/passwd",
            "open a log file and display it",
            "view the source code of a script",
            "cat a file on disk",
            "load a wordlist from a file",
        ],
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read."},
                "offset": {"type": "integer",
                           "description": "0-based line to start at (default 0)."},
                "limit": {"type": "integer",
                          "description": "Max number of lines to read."},
            },
            "required": ["path"],
        },
    ),
    "write_file": (
        _tool_write_file,
        # short
        "Create, overwrite, or append to a file.",
        # normal
        "Create or overwrite a file with the given content (set append=true to "
        "append). Parent directories are created as needed.",
        # long
        "Writes text content to a file, creating any missing parent directories "
        "along the way. By default it creates a new file or overwrites an existing "
        "one; set append=true to add to the end instead of replacing it. Use it "
        "whenever the task is to create, save, generate, output, store, dump or "
        "append content to a file — writing a report or notes, saving scan results "
        "or a payload to disk, creating a script or configuration file, generating "
        "a wordlist, or logging output for later. For changing only part of an "
        "existing file rather than replacing the whole thing, prefer edit_file. "
        "Keywords: create file, save, write, output to file, generate file, store, "
        "dump to disk, append, make a file, save results, redirect to file.",
        # examples
        [
            "save the scan results to a file",
            "create a new script file",
            "write a report to disk",
            "append a line to a log file",
            "generate a configuration file",
            "store some output in a file",
        ],
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write."},
                "content": {"type": "string", "description": "Content to write."},
                "append": {"type": "boolean",
                           "description": "Append instead of overwrite (default false)."},
            },
            "required": ["path", "content"],
        },
    ),
    "edit_file": (
        _tool_edit_file,
        # short
        "Replace an exact piece of text inside an existing file.",
        # normal
        "Replace an exact string in a file. old_string must be unique unless "
        "replace_all=true. Fails if old_string is missing or ambiguous.",
        # long
        "Performs a precise search-and-replace inside an existing file: it finds "
        "an exact substring (old_string) and replaces it with new_string. The "
        "match must be unique unless replace_all=true is passed, in which case "
        "every occurrence is replaced. Use it for surgical edits that keep the "
        "rest of the file intact — changing a value in a config, patching a line "
        "of code, fixing a setting, toggling a flag, or updating a single entry — "
        "rather than rewriting the whole file with write_file. It fails safely if "
        "the target text is missing or ambiguous, so it will not silently corrupt "
        "a file. Keywords: edit, modify, change, replace text, patch, update line, "
        "substitute, find and replace, tweak file, alter, fix in file.",
        # examples
        [
            "change a value in a configuration file",
            "replace a string inside a file",
            "patch a line of code",
            "update a single setting in a file",
            "fix a typo in a file",
            "toggle a flag in the config",
        ],
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to edit."},
                "old_string": {"type": "string",
                               "description": "Exact text to replace."},
                "new_string": {"type": "string",
                               "description": "Replacement text."},
                "replace_all": {"type": "boolean",
                                "description": "Replace every occurrence (default false)."},
            },
            "required": ["path", "old_string", "new_string"],
        },
    ),
    "list_dir": (
        _tool_list_dir,
        # short
        "List the entries of a directory.",
        # normal
        "List a directory's entries with type and size.",
        # long
        "Lists the contents of a directory, showing each entry's name, whether it "
        "is a file or a subdirectory, and file sizes. Use it whenever the task is "
        "to see, browse, explore, enumerate or inspect what is inside a folder — "
        "checking which files exist before reading them, exploring a target's "
        "filesystem, discovering the name of a file, or getting an overview of a "
        "directory's structure. It is not recursive and does not search inside "
        "files: to find text within files use grep, and to read one file use "
        "read_file. Keywords: list directory, ls, dir, browse folder, show files, "
        "enumerate directory, what is in this folder, contents of directory, file "
        "listing, directory tree.",
        # examples
        [
            "list the files in a directory",
            "show me what is in this folder",
            "browse the contents of a directory",
            "what files exist in the target's home directory",
            "enumerate a directory before reading its files",
        ],
        {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Directory to list (default: current)."},
            },
        },
    ),
    "grep": (
        _tool_grep,
        # short
        "Search inside files for a text pattern (regex).",
        # normal
        "Search file contents for a regular expression under a path. Returns "
        "matching lines as path:line: text. Skips binary and VCS dirs.",
        # long
        "Recursively searches the contents of files under a given path for lines "
        "matching a regular expression, returning each hit as path:line: text. It "
        "can match case-insensitively and can be restricted to files matching a "
        "glob such as *.py or *.conf, and it automatically skips binary files and "
        "version-control/build directories. Use it whenever the task is to find, "
        "search, look for, locate or grep some text, string, pattern, keyword, "
        "credential, token, IP address, URL or piece of code across one or many "
        "files — hunting for secrets in a codebase, finding where a configuration "
        "value is set, locating a function definition, or scanning logs for a "
        "term. To read a whole file use read_file; to list a directory use "
        "list_dir. Keywords: grep, search text, find string, pattern match, regex "
        "search, look for, locate in files, scan files for, find keyword, ripgrep.",
        # examples
        [
            "search for a password across the codebase",
            "find where a configuration value is set",
            "grep for a string in a set of files",
            "locate a function definition in the source",
            "scan log files for an IP address",
            "find every file that mentions a keyword",
        ],
        {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",
                            "description": "Regular expression to search for."},
                "path": {"type": "string",
                         "description": "File or directory to search (default: current)."},
                "ignore_case": {"type": "boolean",
                                "description": "Case-insensitive match (default false)."},
                "glob": {"type": "string",
                         "description": "Only search files matching this glob (e.g. *.py)."},
            },
            "required": ["pattern"],
        },
    ),
    "find_files": (
        _tool_find_files,
        # short
        "Find files by name pattern (glob) under a directory.",
        # normal
        "Recursively find files whose NAME matches a glob (e.g. *.conf, nginx.conf, "
        "id_rsa) under a path. Returns the matching file paths. Skips VCS/build "
        "dirs. Use grep to search file CONTENTS instead.",
        # long
        "Recursively walks a directory and returns the paths of files whose name "
        "matches a shell glob pattern such as *.conf, *.py, id_rsa, *.key or "
        "backup*.sql, optionally case-insensitively, skipping version-control and "
        "build directories. Use it whenever the task is to find, locate, discover "
        "or search for a file BY ITS NAME — answering questions like where is a "
        "configuration file, find every file with a given extension, locate SSH "
        "keys or credentials files by filename, list all logs, or figure out where "
        "something lives on disk before reading it. It matches names, not contents "
        "(use grep to search inside files) and, unlike list_dir, it descends into "
        "subdirectories. It is the structured, reliable alternative to running "
        "`find` or `ls -R` through the shell. Keywords: find file, locate file, "
        "where is, search by name, filename, wildcard, glob, find command, ls -R, "
        "discover files, *.ext, look for a file.",
        # examples
        [
            "find all .conf files under /etc",
            "where is the nginx configuration file",
            "locate files named id_rsa",
            "find every python file in this project",
            "search for a file by name",
            "list all .log files on the system",
        ],
        {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",
                            "description": "Filename glob to match (e.g. *.conf, nginx.conf)."},
                "path": {"type": "string",
                         "description": "Directory to search under (default: current)."},
                "ignore_case": {"type": "boolean",
                                "description": "Case-insensitive name match (default false)."},
                "max_results": {"type": "integer",
                                "description": "Stop after this many matches (default 200)."},
            },
            "required": ["pattern"],
        },
    ),
    "http_request": (
        _tool_http_request,
        # short
        "Make an HTTP request and return the response.",
        # normal
        "Make an HTTP request and return the status, response headers and body. "
        "Use for web/API reconnaissance.",
        # long
        "Sends an HTTP or HTTPS request to a URL and returns the response status "
        "code, response headers and body. It supports GET, POST, PUT and other "
        "methods, custom request headers, and a request body for POST/PUT, and it "
        "sends a browser-like User-Agent by default so servers that reject scripts "
        "still respond (the caller can override it). Use it for web and API "
        "reconnaissance and interaction: fetching a web page or API endpoint, "
        "checking response headers and status codes, probing for technologies or "
        "security headers, calling a REST/JSON API, downloading text content, "
        "testing an endpoint, or sending crafted requests. For a full "
        "browser-driven crawl or for binary/non-text downloads prefer run_command "
        "with curl or wget. Keywords: http, https, web request, fetch url, curl, "
        "wget, download page, api call, rest, json, get, post, request headers, "
        "web recon, hit an endpoint, probe url.",
        # examples
        [
            "fetch a web page",
            "check the HTTP response headers of a site",
            "call a REST or JSON API endpoint",
            "download the text content of a URL",
            "send a POST request to test an API",
            "probe a URL for its security headers",
        ],
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "method": {"type": "string",
                           "description": "HTTP method (default GET)."},
                "headers": {"type": "object",
                            "description": "Request headers as a key/value object."},
                "body": {"type": "string",
                         "description": "Request body (for POST/PUT)."},
            },
            "required": ["url"],
        },
    ),
}


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing (identical wire protocol to demo_server.py)
# --------------------------------------------------------------------------- #
def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tools_list():
    # `description` stays the standard model-facing (normal) text so any vanilla
    # MCP client still works. `shortDescription` / `longDescription` are extra
    # fields our own client reads for the catalog and the RAG index; unknown
    # fields are ignored by clients that don't care about them.
    return [
        {
            "name": name,
            "description": normal,
            "shortDescription": short,
            "longDescription": long,
            "exampleQueries": examples,
            "inputSchema": schema,
        }
        for name, (_h, short, normal, long, examples, schema) in TOOLS.items()
    ]


def _call_tool(name, arguments):
    entry = TOOLS.get(name)
    if entry is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}
    handler = entry[0]
    try:
        text = handler(arguments or {})
        return {"content": [{"type": "text", "text": str(text)}]}
    except Exception as exc:
        return {"content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True}


def handle_message(msg):
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
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
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "purr_toolkit_selftest.txt")
    checks = [
        ("tools/list", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ("run_command", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "run_command",
                                    "arguments": {"command": "echo hello && whoami"}}}),
        ("write_file", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "write_file",
                                   "arguments": {"path": tmp, "content": "alpha\nbeta\n"}}}),
        ("read_file", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "read_file", "arguments": {"path": tmp}}}),
        ("edit_file", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "edit_file",
                                  "arguments": {"path": tmp, "old_string": "beta",
                                                "new_string": "GAMMA"}}}),
        ("grep", {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                  "params": {"name": "grep",
                             "arguments": {"pattern": "GAMMA", "path": tmp}}}),
        ("list_dir", {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "list_dir",
                                 "arguments": {"path": os.path.dirname(tmp)}}}),
    ]
    for label, req in checks:
        resp = handle_message(req)
        result = resp.get("result", {})
        if label == "tools/list":
            tools = result.get("tools", [])
            names = [t["name"] for t in tools]
            print(f"[{label}] -> {names}")
            # Confirm every tool exposes all three descriptions.
            for t in tools:
                have = [k for k in ("shortDescription", "description",
                                    "longDescription") if t.get(k)]
                mark = "ok" if len(have) == 3 else f"MISSING {set(('shortDescription','description','longDescription')) - set(have)}"
                print(f"    {t['name']:<13} short/normal/long: {mark} "
                      f"({len(t.get('shortDescription',''))}/"
                      f"{len(t.get('description',''))}/"
                      f"{len(t.get('longDescription',''))} chars) "
                      f"examples: {len(t.get('exampleQueries', []))}")
        else:
            text = result.get("content", [{}])[0].get("text", "")
            print(f"[{label}] -> {text.splitlines()[0] if text else ''}")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        serve()
