"""purragent_core._shared — extracted from monolithic purragent.py (Phase A refactor)."""

from rich.console import Console
import agent_context
import os
import re
import run_mode
import wire_format

FILL_FRAC = agent_context.FILL_FRAC



OUTPUT_FLOOR = agent_context.OUTPUT_FLOOR



AGENT_KEEP_LAST_GROUPS = agent_context.AGENT_KEEP_LAST_GROUPS



AGENT_OUTPUT_RESERVE_TOK = agent_context.AGENT_OUTPUT_RESERVE_TOK



AGENT_DBCTX_FRAC = agent_context.AGENT_DBCTX_FRAC



AGENT_TRIM_PLACEHOLDER = agent_context.AGENT_TRIM_PLACEHOLDER



_split_msg_groups = agent_context.split_msg_groups



_msgs_chars = agent_context.msgs_chars



_msgs_budget_chars = agent_context.msgs_budget_chars



_trim_agent_msgs = agent_context.trim_agent_msgs



_oai_tools_to_anthropic = wire_format.oai_tools_to_anthropic



_oai_msgs_to_anthropic = wire_format.oai_msgs_to_anthropic



_BUILTIN_TOOLS_SERVER = run_mode.BUILTIN_TOOLS_SERVER



_READONLY_TOOLS = run_mode.READONLY_TOOLS



_READONLY_BINS = run_mode.READONLY_BINS



_DANGER_PATTERNS = run_mode.DANGER_PATTERNS



_has_write_redirect = run_mode.has_write_redirect



_classify_command = run_mode.classify_command



_needs_confirm = run_mode.needs_confirm



_approval_key = run_mode.approval_key



TOOL_NAME = "purragent"



VERSION   = "1.0.0"



DEFAULT_GREETING = "Hacker"      # "Welcome back <greeting>!" — change with /greeting



_NO_MODEL = object()             # picker sentinel: detach the model (debugging)



VIOLET    = "#b46cff"     # single-colour fill for the paw logo + accents



ORANGE    = "#d19a66"     # debug-only accents (e.g. /context budget diagnostics)



_HERE = os.path.dirname(os.path.abspath(__file__))



LOGO_PATHS = {
    "open":   os.path.join(_HERE, "purragent_logo.ans"),
    "blink":  os.path.join(_HERE, "purragent_logo_blink.ans"),
    "squint": os.path.join(_HERE, "purragent_logo_squint.ans"),
}



FALLBACK_PAW = "  _   _\n (_) (_)\n(_)   (_)\n  (___)"



BLINK_CYCLE   = 4.5



BLINK_LEN     = 0.16



SQUINT_CYCLE  = 11.0



SQUINT_LEN    = 0.9



BLINK_REFRESH = 0.05



SLASH = [
    ("/model",    "switch the attached model (or detach)"),
    ("/mode",     "set how the agent runs (auto / semi-auto / confirm / plan)"),
    ("/mcp",      "manage MCP servers"),
    ("/doctor",   "check which hacktools need a program installed"),
    ("/hack",     "run the auto-hacking loop against a target"),
    ("/memory",   "view or forget what the model has remembered"),
    ("/upgrade",  "re-launch purragent as root (sudo)"),
    ("/debug",    "toggle showing the raw request sent to the model"),
    ("/greeting", "set the welcome name (e.g. /greeting Neo)"),
    ("/context",  "show how much of the context window is used"),
    ("/setcontext", "set the max context this session (e.g. 32k, or 'default' to reset)"),
    ("/help",     "show commands and usage"),
    ("/clear",    "clear the conversation"),
    ("/exit",     "quit purragent"),
]



HACK_SLASH = [
    ("/target",   "show the recorded hacking-mode target database"),
    ("/start",    "start hacking the recorded target"),
    ("/stop",     "stop the agent (pause hacking)"),
    ("/status",   "show the background scan status"),
]



SLASH_SUBCOMMANDS = {
    "/mcp": [
        ("add",     "add a connect-only MCP server by URL"),
        ("enable",  "enable a server (pull its tools)"),
        ("disable", "disable a server"),
        ("remove",  "remove an MCP server (and all its data)"),
    ],
    "/memory": [
        ("delete",  "forget an entry by its number"),
        ("clear",   "forget everything"),
    ],
}



_MCP_NAME_SUBS = ("remove", "rm", "delete", "enable", "disable")



DEFAULT_MODE = "auto"



AGENT_MODES = [
    ("auto",      "run commands automatically, without asking"),
    ("semi-auto", "ask for permission only for risky actions"),
    ("confirm",   "ask before running each command"),
    ("plan",      "plan only — describe actions, don't execute"),
]



BANNER_COMMANDS = [
    ("/model",   "switch model"),
    ("/help",    "show help"),
    ("/mcp",     "MCP servers"),
    ("/upgrade", "run as root"),
    ("/hack",    "hack a target"),
]



PURRAGENT_SYSTEM = (
    "You are purragent, a console assistant for authorized penetration testing "
    "and security research inside PurrSh3ll. Be concise and practical. "
    "Basic host facts are given in the <env> block below — use them directly and "
    "do not call tools to discover what is already there (user, home, OS, cwd, date)."
)



console = Console()



MEMORY_KINDS = ("instruction", "fact")



FINDINGS_MAX = 50    # cap stored findings (agent-written — unlike the few user memories)



_LOCAL_CTX_PROVIDERS = frozenset({"ollama", "llamacpp", "lmstudio", "jan", "koboldcpp"})



PLAN_MODE_NOTE = (
    "You are in PLAN mode. Do NOT call any tools. Produce a concise, numbered plan "
    "of the concrete steps and exact shell commands you would run to accomplish the "
    "task, each with a short rationale. The user will switch to another mode to "
    "actually execute."
)



MCP_PROBE_TIMEOUT = 20.0   # hard cap (s) on a background HTTP liveness probe



ENABLE_TIMEOUT = 60.0      # hard cap (s) on a background enable (tool fetch);



_PKG_HINT = {
    "nxc": "apt: netexec",
    "impacket-secretsdump": "apt: impacket-scripts",
    "impacket-wmiexec": "apt: impacket-scripts",
    "impacket-GetUserSPNs": "apt: impacket-scripts",
    "dig": "apt: dnsutils", "ldapsearch": "apt: ldap-utils",
    "rpcclient": "apt: samba-common-bin", "showmount": "apt: nfs-common",
    "redis-cli": "apt: redis-tools", "mongosh": "apt: mongodb-mongosh",
    "mysql": "apt: default-mysql-client", "psql": "apt: postgresql-client",
    "searchsploit": "apt: exploitdb", "msfvenom": "apt: metasploit-framework",
    "theHarvester": "apt: theharvester", "bloodhound-python": "pip: bloodhound",
    "certipy": "pip: certipy-ad", "kerbrute": "github: ropnop/kerbrute",
    "gau": "go: lc/gau", "katana": "go: projectdiscovery/katana",
    "dalfox": "go: hahwul/dalfox", "subfinder": "go: projectdiscovery/subfinder",
    "sshpass": "apt: sshpass",
}



AGENT_TEMPERATURE = 0.2



EXTRACT_TURN_MAX_SECONDS = 90.0    # phase-5 per-command finding extraction



AGENT_TURN_MAX_SECONDS = 180.0     # phase-4.5 review + phase-5 exploit agent turns



TOOL_LOOP_MAX_ROUNDS = 8        # plain chat / single-action tasks



PLANNED_MAX_ROUNDS   = 15       # raised ceiling once the model has an active update_plan



PLAN_MAX_STEPS       = 6        # soft cap on plan length (weak models drift past ~6 steps)



_THINK_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"   # same braille frames pschat uses



ANTHROPIC_VERSION    = "2023-06-01"



ANTHROPIC_MAX_TOKENS = 4096          # required by the Messages API; caps reply length



DISCOVERY_MAX_ROUNDS = 3     # how many times request_tool may be used per turn



RETRIEVE_TOP_N       = 3     # tools surfaced per request_tool call



MAX_ACTIVE_TOOLS     = 12    # cap on accumulated full schemas (context budget)



TOOLS_RESERVATION_TOKENS = 900



MEMORY_LOOKUP_TOKENS = 2000



SUMMARIZED_CAP_FRAC   = 0.30   # cap on kept summary; older summary is recompressed



FINDINGS_CAP_FRAC     = 0.20   # cap on findings context once the DB is wired



FINDINGS_FLOOR_TOKENS = 0      # reservation held for findings — 0 until DB attached



META_TOOL_NAME = "request_tool"



_META_TOOL = {
    "type": "function",
    "function": {
        "name": META_TOOL_NAME,
        "description": (
            "Request a tool by describing, in natural language, what you need to "
            "do. The matching tools (with their full parameters) will then be "
            "provided so you can call them. Use this whenever you need to act on "
            "the system — do not guess tool names. Describe the CAPABILITY only, "
            "in a few words; never put the actual data (file contents, target "
            "names, payloads, arguments) in the request — that dilutes the match. "
            "Save the data for when you call the real tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "need": {
                    "type": "string",
                    "description": (
                        "A short capability phrase describing the action you "
                        "need, NOT the data it will operate on. Good: 'write text "
                        "to a file', 'scan a host for open ports', 'read a "
                        "configuration file'. Bad: 'create cats.txt with the "
                        "content \"...\"' — leave the filename/content/payload out "
                        "and provide them later as the tool's arguments."
                    ),
                },
            },
            "required": ["need"],
        },
    },
}



ENABLE_HACK_TOOL_NAME = "enable_hacking_mode"



_ENABLE_HACK_TOOL = {
    "type": "function",
    "function": {
        "name": ENABLE_HACK_TOOL_NAME,
        "description": (
            "Switch the console into hacking mode when the user clearly wants to "
            "start an authorised offensive engagement against a specific target "
            "(attack it, pentest it, a CTF / Hack The Box box). Set enable=true to "
            "propose it — the user is still asked to confirm. Do NOT put target "
            "details here; they are collected after confirmation. Do not call this "
            "for general security questions or explanations."),
        "parameters": {
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean",
                    "description": ("true to turn hacking mode on (the user then "
                                    "confirms); false does nothing."),
                },
            },
            "required": ["enable"],
        },
    },
}



_HACK_TRIGGER_GUIDE = (
    "HACKING MODE: if the user clearly wants to start an offensive engagement "
    "against a specific target (attack it, pentest it, a CTF/HTB box), call "
    "enable_hacking_mode with enable=true instead of guessing tools — the user "
    "then confirms. Don't call it for general security questions or explanations."
)



SAVE_MEMORY_TOOL_NAME = "save_memory"



_SAVE_MEMORY_TOOL = {
    "type": "function",
    "function": {
        "name": SAVE_MEMORY_TOOL_NAME,
        "description": (
            "Manage what you remember for the rest of this session, when "
            "the USER explicitly asks. action='save' persists a standing INSTRUCTION (how "
            "to behave, something to always do/add) or a FACT to keep; action='delete' "
            "forgets a previously stored memory (match it by the text shown in the "
            "REMEMBERED / USER INSTRUCTIONS block). Only call this when the user clearly "
            "asks to remember/save/note something, to always do something, or to forget/"
            "stop remembering something — never for a normal answer. Store the distilled "
            "point, not the whole message."),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["save", "delete"],
                           "description": "'save' (default) to remember, 'delete' to "
                                          "forget a stored memory."},
                "text": {"type": "string",
                         "description": "For save: the distilled thing to remember, one "
                                        "line. For delete: the stored memory to forget "
                                        "(its exact text or a distinctive part of it)."},
                "kind": {"type": "string", "enum": ["instruction", "fact"],
                         "description": ("(save only) 'instruction' = a standing rule to "
                                         "always follow (e.g. always add X to answers); "
                                         "'fact' = a piece of information to keep.")},
            },
            "required": ["text"],
        },
    },
}



_MEMORY_GUIDE = (
    "MEMORY: when the user gives a STANDING instruction (do X every time / always / from "
    "now on / at the end of each answer / za każdym razem / każdorazowo) or asks you to "
    "remember or forget something, call save_memory ONCE to persist it — a single call, "
    "then stop (do not save it again, delete it, or re-save). The stored USER "
    "INSTRUCTIONS above already apply on every turn, so just keep following them.")



UPDATE_PLAN_TOOL_NAME = "update_plan"



_UPDATE_PLAN_TOOL = {
    "type": "function",
    "function": {
        "name": UPDATE_PLAN_TOOL_NAME,
        "description": (
            "Record or update a short ordered to-do plan for a MULTI-STEP task, so you "
            "keep track of progress across tool calls. Send the WHOLE plan every time "
            f"(3-{PLAN_MAX_STEPS} steps, resent in full), each with a status: 'todo' (not "
            "started), 'doing' (the one step you are working on now), or 'done'. Call this "
            "first to lay out the plan, then again after finishing a step to move it to "
            "'done' and mark the next 'doing'. Do NOT use it for a simple question or a "
            "single action — only when the task genuinely has several distinct steps."),
        "parameters": {
            "type": "object",
            "properties": {
                "steps": {
                    "type": "array",
                    "description": ("The full plan in order. Resend every step each time "
                                    "with its current status — this replaces the prior "
                                    "plan, it is not a delta."),
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string",
                                     "description": "One concise step (an action to take)."},
                            "status": {"type": "string",
                                       "enum": ["todo", "doing", "done"],
                                       "description": "Progress on this step."},
                        },
                        "required": ["text", "status"],
                    },
                },
            },
            "required": ["steps"],
        },
    },
}



_PLAN_GUIDE = (
    "PLANNING: for a MULTI-STEP task (roughly 3+ distinct actions — e.g. enumerate a "
    "host, build something in stages, a targeted pentest/HTB task), call update_plan "
    f"ONCE up front with a short ordered plan (3-{PLAN_MAX_STEPS} steps), then call it "
    "again after each step to keep statuses current (finished → 'done', the step you are "
    "on → 'doing'). The current plan is shown to you each turn; work through it and stop "
    "when every step is done. For a simple question or a single action, do NOT plan.")



SAVE_FINDING_TOOL_NAME = "save_finding"



_SAVE_FINDING_TOOL = {
    "type": "function",
    "function": {
        "name": SAVE_FINDING_TOOL_NAME,
        "description": (
            "Record a concrete FINDING you discovered about the target or system — an "
            "open port, a service/version, a credential, a vulnerability, a path, a "
            "misconfiguration. It is stored and shown back to you on later turns so you "
            "can build on it and include it in your final summary. Save ONE distilled "
            "fact per call (the important bit, not a whole tool dump); call again for "
            "each new finding. This is for DISCOVERIES about the target, NOT user "
            "preferences (those go to save_memory)."),
        "parameters": {
            "type": "object",
            "properties": {
                "finding": {"type": "string",
                            "description": ("One concise discovered fact — the important "
                                            "bit only, e.g. 'SMB anonymous listing allowed; "
                                            "share backups readable'.")},
                "where": {"type": "string",
                          "description": ("Optional: where it applies — host/IP, port, or "
                                          "service (e.g. '10.10.10.5:445 smb').")},
            },
            "required": ["finding"],
        },
    },
}



_FINDING_GUIDE = (
    "FINDINGS: when you DISCOVER a concrete fact about the target/system (open port, "
    "service version, credential, vulnerability, path, misconfiguration), call "
    "save_finding ONCE with that distilled fact so it is kept and available for your "
    "final summary. One fact per call. Do NOT put user preferences here — those go to "
    "save_memory.")



_SEQUENCING_GUIDE = (
    "SAVING TOOL OUTPUT TO A FILE: when the task is to run something AND save or "
    "report its output (e.g. 'scan X and save the results to a file'), do it IN "
    "ORDER — first call the tool that produces the data and WAIT for its result, "
    "then, on a LATER turn once you actually have that output, call write_file with "
    "the REAL content. Never write a placeholder like '[results will appear here]', "
    "and never call write_file for the output in the SAME turn as the tool that "
    "generates it: at that point you do not have the data yet, so the file would be "
    "saved empty.")



_DISCOVERY_GUIDE = (
    "TOOLS: you can act on the system through tools. The catalog below has two "
    "sections. The 'built-in' tools are listed with their exact name and "
    "parameters (required bare, optional in [brackets]) — call these DIRECTLY by "
    "that exact name with those arguments; do not use request_tool for them. For "
    "the 'others' section, only capabilities are shown, not names: call the "
    "`request_tool` function with a natural-language description of what you "
    "need, and the matching tools will be given to you with their parameters so "
    "you can call them. If a tool you were already given fits, call it directly — "
    "only call `request_tool` again if none fit. If the task needs no tool, just "
    "answer normally."
)



_TOOL_AVAIL_CACHE: dict = {}      # binary -> installed?, per session



_HACK_ANNOUNCEMENT = (
    "Hacking mode enabled — it works on a single target at a time."
)



_HACK_TRANSLATE_INSTRUCTIONS = (
    "Translate the message below into the language the user has been writing in "
    "during this conversation. If they were writing in English, or you are not "
    "sure, return it unchanged. Output ONLY the translated message — no preamble, "
    "no quotes, no notes.\n\nMessage:\n" + _HACK_ANNOUNCEMENT
)



_HACK_GOAL = "flag"



_RECORD_TARGET_TOOL = {
    "type": "function",
    "function": {
        "name": "record_target",
        "description": (
            "Store what the user just told you about the single engagement target. "
            "Fill EVERY field the user mentioned — the ports, the service on a port "
            "and the credentials matter as much as the IP; do NOT stop after the IP. "
            "Extract only facts the user actually stated; never invent or guess."),
        "parameters": {
            "type": "object",
            "properties": {
                "ip":       {"type": "string", "description": "target IP address"},
                "hostname": {"type": "string"},
                "url":      {"type": "string"},
                "os":       {"type": "string"},
                "platform": {"type": "string",
                             "description": "linux / windows / ad / web / other"},
                "ports": {
                    "type": "array",
                    "description": "Every port NUMBER the user mentioned.",
                    "items": {"type": "integer"},
                },
                "services": {
                    "type": "array",
                    "description": "Which service runs on which port.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "port": {"type": "integer"},
                            "name": {"type": "string"},
                        },
                        "required": ["port", "name"],
                    },
                },
                "credentials": {
                    "type": "array",
                    "description": "Username/password pairs the user has.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "secret":   {"type": "string"},
                            "type":     {"type": "string",
                                         "description": "password/hash/ssh_key/token"},
                        },
                        "required": ["username"],
                    },
                },
                "paths": {
                    "type": "array",
                    "description": "Known web paths / URLs / endpoints.",
                    "items": {"type": "string"},
                },
                "notes": {
                    "type": "string",
                    "description": "Anything relevant that doesn't fit the fields above.",
                },
                "other_targets": {
                    "type": "array",
                    "description": (
                        "Extra DISTINCT hosts if the user described more than one "
                        "(the first goes in `ip`). The SAME host's IP + hostname + "
                        "URL are ONE target — do not list those."),
                    "items": {"type": "string"},
                },
            },
        },
    },
}



_RECORD_SYS = (
    "The user is describing the target for an authorised offensive engagement. "
    "Hacking mode handles ONE target at a time. Call record_target and fill EVERY "
    "detail the user gave — the ports, the service on a port and the credentials "
    "matter as much as the IP; do NOT stop after the IP. Extract only what the user "
    "actually said; never invent. If they gave several distinct hosts, put the "
    "first in `ip` and the rest in `other_targets`.\n\n"
    "Example — user says: 'ip 1.2.3.4 ports 22 80 445, http on 80, creds "
    "bob:hunter2' → ip=\"1.2.3.4\", ports=[22,80,445], "
    "services=[{\"port\":80,\"name\":\"http\"}], "
    "credentials=[{\"username\":\"bob\",\"secret\":\"hunter2\"}]."
)



PORT_SCAN_MINUTES = 10



EXPLOIT_CMD_MINUTES = 3        # per-command time budget in phase 5 (service exploitation)



_PORT_PASS_LABEL = {
    "fast": "fast port discovery",
    "full-lo": "full low ports discovery",
    "full-hi": "full high ports discovery",
    "udp": "udp port discovery",
}



_STATE_TAG = {"complete": ("complete", "default"),    # normal, like the rest of the line
              "error": ("failed", "red"),
              "aborted": ("aborted", "magenta")}



_VULN_SSL = "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params"



_VULN_SCRIPTS = {
    "microsoft-ds": "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-vuln-ms10-061,smb-vuln-cve2009-3103,smb-double-pulsar-backdoor,"
                    "smb-security-mode,smb2-security-mode,smb-enum-users",
    "netbios-ssn":  "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,"
                    "smb-security-mode,smb-enum-users",
    "http":         "http-shellshock,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
                    "http-vuln-cve2014-3704,http-vuln-cve2012-1823,http-vuln-cve2017-1001000,"
                    "http-vuln-misfortune-cookie,http-default-accounts",
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



_VULN_TLS_PORTS = {443, 465, 563, 636, 853, 990, 992, 993, 995, 8443}



_VULN_AUTH_TITLE = {
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



_CVE_STORE_CAP = 20        # newest CVEs kept per service (keeps findings readable)



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



_EXPLOIT_FILL_OK = re.compile(r"<[A-Za-z]")        # any leftover <PLACEHOLDER> → unrunnable



_EXPLOIT_DENY_BINS = {
    "responder", "ntlmrelayx", "impacket-ntlmrelayx", "mitm6", "coercer",
    "petitpotam", "printerbug", "pre2k",
    "hashcat", "john", "hydra", "medusa", "patator", "ncrack", "kerbrute",
    "msfconsole", "msfvenom",
}



CURL_MAX_TIME_SECONDS = 60         # cap each curl request so it can't stall the budget



_EXPLOIT_EXTRACT_SYSTEM = (
    "You are a penetration-testing assistant. You are given the raw output of a single "
    "enumeration command run against one service. Extract ONLY the security-relevant "
    "facts: credentials, usernames, shares, versions, hostnames/domains, readable or "
    "writable files/paths, misconfigurations, and anything directly actionable. Be "
    "terse — a few short lines, no preamble, no advice. If there is nothing useful, "
    "reply with exactly: NONE")



REVIEW_MAX_ROUNDS = 4



REVIEW_MAX_TOOLCALLS = 6



REVIEW_BUDGET_MINUTES = 8



_REVIEW_TOOLS = {"port_discovery", "service_discovery", "script_scan"}



_REVIEW_SYSTEM = (
    "You are a penetration-testing assistant reviewing the automated NMAP recon "
    "(port scan, service/version detection, NSE) already run against the target — its "
    "findings are given below. Your only job here is to judge whether that nmap recon "
    "was SUFFICIENT, and if not, re-run nmap with BETTER PARAMETERS via the tools "
    "provided. Examples: a firewalled/laggy host that may have dropped ports → slower "
    "timing or a wider/full port range; ports that looked filtered → different host "
    "discovery; a service that came back unknown/tcpwrapped → higher version intensity "
    "or OS detection; a specific product/version → a targeted NSE script. Only re-scan "
    "when the current results look incomplete or unreliable — otherwise do nothing. Do "
    "NOT do service-specific exploitation, brute-force or credentialed actions (that is "
    "the next phase). When done, reply with a 1-3 line summary of what (if anything) "
    "the extra nmap runs changed, then stop.")



_REVIEW_TASK = ("Review the nmap recon above. If it looks complete and reliable, say so "
                "and stop. Otherwise re-run nmap with better parameters (range/timing/"
                "UDP/version-intensity/OS/NSE) where it clearly helps, then summarise.")



_AGENT_SECRET_ARGS = {"password", "hash", "bearer", "api_token"}



SERVICE_REVIEW_MAX_ROUNDS = 3



SERVICE_REVIEW_MAX_TOOLCALLS = 5



SERVICE_REVIEW_BUDGET_MINUTES = 5



_SERVICE_REVIEW_SYSTEM = (
    "You are a penetration tester reviewing ONE service after its deterministic "
    "no-credential enumeration. Below are the findings for this service and the exact "
    "commands already run against it. Decide whether any FURTHER enumeration or "
    "exploitation command would add real value here, and if so run it via the tools. "
    "Do NOT repeat any command already run. Do NOT brute-force and do NOT use "
    "credentials you were not given (those are handled elsewhere). Stay on THIS host "
    "and THIS service. If nothing more is worth running, reply with a one-line note "
    "saying so and stop.")



EXPLOIT_AGENT_MAX_ROUNDS = 6



EXPLOIT_AGENT_MAX_TOOLCALLS = 12



EXPLOIT_AGENT_BUDGET_MINUTES = 12



_EXPLOIT_AGENT_TOOLS = {
    "smb_client", "netexec_smb", "ldap_search", "rpc_enum", "secretsdump",
    "impacket_exec", "kerberos_roast", "enum4linux", "smbmap", "certipy",
    "bloodhound_python", "mysql_query", "mssql_query", "psql_query", "redis_cli",
    "mongo_query", "ssh_exec", "winrm_exec", "ftp_transfer", "sqlmap", "nuclei_scan",
    "wpscan", "http_request", "git_dump", "hash_identify", "default_creds",
    "cve_lookup", "payload_gen",
    "linux_privesc_enum", "windows_privesc_enum", "gtfobins_lookup", "read_file",
}



_EXPLOIT_AGENT_SYSTEM = (
    "You are a penetration tester doing a final CROSS-SERVICE and PRIVILEGE-ESCALATION "
    "pass. Every service has already been enumerated and individually reviewed; the "
    "combined findings — including any credentials or artefacts discovered — are below. "
    "Do the two things a per-service review cannot:\n"
    "1) CORRELATE ACROSS SERVICES: reuse a credential or artefact found on one service "
    "against another (e.g. FTP creds on SMB, a config password against a database, a "
    "hash dumped from one host used to authenticate to another service).\n"
    "2) ESCALATE PRIVILEGES to capture the flag: where you hold a validated shell login "
    "(ssh/winrm), enumerate local privesc with linux_privesc_enum / windows_privesc_enum "
    "(their output may already be in the findings below), turn a SUID binary or a "
    "`sudo -l` entry into a concrete technique with gtfobins_lookup, run that technique "
    "via ssh_exec / winrm_exec, and read the root/flag file (e.g. /root/root.txt) with "
    "read_file. THE OBJECTIVE IS THE FLAG, including the ROOT flag.\n"
    "Pass credentials as the tools' typed parameters. Do NOT brute-force, do NOT scan "
    "the network broadly, do NOT repeat single-service enumeration already done, and "
    "stay on this host. When the useful follow-ups are exhausted, reply with a short "
    "summary — quoting any flag you captured — and stop.")



_EXPLOIT_AGENT_TASK = (
    "Using the combined findings above: (1) correlate any discovered credential or "
    "artefact across services where it clearly helps, and (2) where you have a shell "
    "login, escalate privileges to capture the flag — enumerate privesc, use "
    "gtfobins_lookup on any SUID/sudo entry, run the technique, and read the root/flag "
    "file. Then summarise, quoting any flag you captured. If there is nothing to do, say "
    "so briefly and stop.")



CRED_VALIDATE_MAX = 40             # hard cap on validation logins per host



_CRED_VALIDATE_TIMEOUT = 45        # seconds per validation login



_NULL_ANON_CREDS = {
    "ftp":     [("anonymous", "", "none"), ("anonymous", "anonymous@", "none")],
    "smb":     [("", "", "none"), ("guest", "", "none")],
    "ldap":    [("", "", "none")],
    "redis":   [("", "", "none")],
    "mongodb": [("", "", "none")],
    "mysql":   [("root", "", "none")],
    "mssql":   [("sa", "", "none")],
    "psql":    [("postgres", "", "none")],
}



_CRED_EXTRACT_SYSTEM = (
    "You are a penetration tester. From the enumeration findings below, extract, grounded "
    "STRICTLY in the text (never guess or invent), two things:\n"
    "1) CREDENTIALS — entries that include a secret: username+password pairs, password "
    "hashes, private keys, or API tokens.\n"
    "2) USERNAMES — possible usernames with NO known secret: enumerated users, account "
    "names, email local-parts, names in configs/banners.\n"
    "Reply with ONLY a JSON object, no prose:\n"
    '{"credentials": [{"username": str, "secret": str, '
    '"type": "password|ntlm_hash|ssh_key|token", '
    '"service_hint": "<ssh/smb/ftp/mysql/… or *>", "source": "<where-from>", '
    '"confidence": <0.0-1.0>}], '
    '"usernames": [{"username": str, "service_hint": "<service or *>", '
    '"source": "<where-from>"}]}\n'
    "Put an entry in credentials ONLY if it has a secret; a bare username goes in "
    "usernames. If a section is empty use []. If nothing at all, reply: "
    '{"credentials": [], "usernames": []}')



FLAG_HUNT_MAX = 8                 # hard cap on loot commands per host



FLAG_HUNT_BUDGET_MINUTES = 5      # wall-clock ceiling for the flag hunt



_FLAG_HUNT_TIMEOUT = 60           # seconds per loot command



_LOOT_SERVICES = {"ssh", "winrm"}    # services that give real command execution



_FLAG_RE = re.compile(r"\b(?:flag|HTB|THM|FLAG|picoCTF|CTF)\{[^}\r\n]{1,200}\}")



_HASH32_LINE = re.compile(r"^[0-9a-fA-F]{32}$")



_NIX_LOOT = (
    "cat /root/root.txt /root/flag.txt /root/flag /home/*/user.txt /home/*/flag.txt "
    "/home/*/flag /flag /flag.txt /var/www/flag* 2>/dev/null; "
    "find / -maxdepth 5 -type f -iname 'flag*' 2>/dev/null | head -n 20; "
    "find / -maxdepth 5 -type f \\( -iname 'user.txt' -o -iname 'root.txt' \\) "
    "2>/dev/null | head -n 20"
)



_WIN_LOOT = (
    "Get-ChildItem C:\\Users,C:\\ -Recurse -Include user.txt,root.txt,flag.txt,flag "
    "-ErrorAction SilentlyContinue -File | Select-Object -First 20 | "
    "ForEach-Object { $_.FullName; Get-Content $_.FullName -ErrorAction SilentlyContinue }"
)



PRIVESC_ENUM_MAX = 4                 # hard cap on privesc sweeps per host



PRIVESC_ENUM_BUDGET_MINUTES = 8      # wall-clock ceiling for the privesc step



_PRIVESC_ENUM_TIMEOUT = 150          # seconds per sweep (find / can be slow)



_PRIVESC_FINDING_CAP = 1800          # chars of sweep output kept in the stored finding



_PRIVESC_SERVICES = {"ssh", "winrm"}    # shell services we can enumerate over



DERIVE_VALIDATE_MAX = 150          # hard cap on derivation login attempts per host



DERIVE_BUDGET_MINUTES = 8          # wall-clock ceiling for the derivation step



_DERIVE_SUFFIXES = ["123", "1", "!", "12345", "2024", "2025"]



_DEFAULT_CREDS = {                 # per service class: a few classic defaults
    "ssh":    [("root", "root"), ("admin", "admin")],
    "ftp":    [("ftp", "ftp"), ("admin", "admin")],
    "mysql":  [("root", "root"), ("root", "mysql")],
    "psql":   [("postgres", "postgres")],
    "mssql":  [("sa", "sa")],
    "smb":    [("administrator", "administrator")],
    "rdp":    [("administrator", "administrator")],
    "telnet": [("root", "root"), ("admin", "admin")],
}



BRUTE_MINUTES = 15                 # per-service hydra deadline



BRUTE_MAX_PARALLEL = 2             # concurrent hydra processes



BRUTE_THREADS = 4                  # hydra -t (parallel logins within one job)



_BRUTE_SERVICES = {                # pshunter service class → hydra module
    "ssh": "ssh", "ftp": "ftp", "smb": "smb", "mysql": "mysql", "mssql": "mssql",
    "psql": "postgres", "rdp": "rdp", "telnet": "telnet", "vnc": "vnc",
}



_BRUTE_SEED_USERS = ["root", "admin", "administrator", "user", "guest", "test",
                     "oracle", "postgres", "mysql", "service"]



_BRUTE_PASS_FILES = [
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
    "/usr/share/wordlists/metasploit/unix_passwords.txt",
]



_BRUTE_FALLBACK_PASSWORDS = [
    "password", "123456", "admin", "root", "toor", "letmein", "password123",
    "qwerty", "welcome", "changeme", "P@ssw0rd", "administrator", "12345678",
    "test", "guest", "1234", "root123", "admin123", "pass123", "secret",
]



_HYDRA_HIT = re.compile(
    r"\[\d+\]\[[^\]]+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S*)")



_REPORT_SYSTEM = (
    "You are a penetration tester writing a SHORT findings report for the operator, "
    "from the recon and service-enumeration results below. Summarise WHAT was found "
    "and why it matters: exposed services, vulnerabilities (known-exploited / high "
    "first), credentials, exposed files or data, and misconfigurations — prioritised, "
    "concise, factual, in plain language (a few short paragraphs or bullets). Do NOT "
    "mention the specific commands or tools that were run. If there is little to "
    "report, say so briefly.")



_STATUS_STATE = {"running": ("default", "running"), "complete": ("green", "complete"),
                 "error": ("red", "error"), "aborted": ("magenta", "aborted")}



_SUMMARY_SYSTEM = (
    "You maintain a running summary of a conversation so its older turns can be dropped "
    "without losing context. Merge the EXISTING SUMMARY with the OLDER TURNS below into "
    "ONE concise summary. Preserve: decisions made, facts/data established, the user's "
    "stated preferences and standing instructions, unfinished threads and open "
    "questions, and important names/paths/values. Drop small talk and redundancy. Write "
    "compact notes (third person, no preamble, no meta-comments).")

