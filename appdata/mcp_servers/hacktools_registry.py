#!/usr/bin/env python3
# PurrSh3ll — hacktools MCP server: the tool registry (name -> builder, description,
# inputSchema), the RAG/catalog metadata, and per-tool timeout/binary/py-lib tables.
# Pure data plus references to the builders in hacktools_tools. Extracted verbatim
# from hacktools_server.py; the server reads these to answer tools/list and dispatch.

from hacktools_tools import *   # noqa: F401,F403 — resolves the _b_* builder refs below


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
    "sqlmap": (
        _b_sqlmap,
        "Test a URL/parameter for SQL injection with sqlmap and, if found, enumerate or "
        "dump data. Active and can be slow. (Credentials/cookies passed on the CLI.)",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL (with params for GET)."},
            "data": {"type": "string", "description": "POST body to test."},
            "cookie": {"type": "string", "description": "Cookie header."},
            "param": {"type": "string", "description": "Focus on this parameter (-p)."},
            "level": {"type": "integer", "description": "Test level 1-5."},
            "risk": {"type": "integer", "description": "Risk 1-3."},
            "action": {"type": "string", "description": "test (default, detect only) · "
                       "dbs · current · dump."},
            "database": {"type": "string", "description": "DB to dump (action=dump)."},
            "table": {"type": "string", "description": "Table to dump (action=dump)."}},
         "required": ["url"]}),
    "wpscan": (
        _b_wpscan,
        "Scan a WordPress site with wpscan — versions, vulnerable plugins/themes and "
        "users. An API token unlocks vulnerability data.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "WordPress site URL."},
            "enumerate": {"type": "string", "description": "wpscan --enumerate value, "
                          "e.g. vp,vt,u (default). vp=vuln plugins, u=users, etc."},
            "api_token": {"type": "string", "description": "WPScan API token (optional, "
                          "for CVE data)."}},
         "required": ["url"]}),
    "enum4linux": (
        _b_enum4linux,
        "Thorough SMB/Windows enumeration with enum4linux-ng: OS, users, groups, shares, "
        "password policy — null session or credentials.",
        {"type": "object", "properties": {
            "host": _H, "username": _USER, "password": _PASS, "domain": _DOMAIN},
         "required": ["host"]}),
    "smbmap": (
        _b_smbmap,
        "Map SMB share access (read/write) with smbmap; optionally recurse the tree. "
        "Null session or credentials (password or NT hash).",
        {"type": "object", "properties": {
            "host": _H, "username": _USER, "password": _PASS, "hash": _HASH,
            "domain": _DOMAIN,
            "share": {"type": "string", "description": "Limit to one share (optional)."},
            "recurse": {"type": "boolean", "description": "Recurse the directory tree."}},
         "required": ["host"]}),
    "certipy": (
        _b_certipy,
        "Enumerate AD Certificate Services with certipy find (-vulnerable) — CA "
        "templates and ESC misconfigurations. Requires domain credentials or NT hash.",
        {"type": "object", "properties": {
            "dc": {"type": "string", "description": "Domain controller host/IP."},
            "domain": {"type": "string", "description": "AD domain, e.g. corp.local."},
            "username": _USER, "password": _PASS, "hash": _HASH},
         "required": ["dc", "domain", "username"]}),
    "testssl": (
        _b_testssl,
        "Deep TLS/SSL audit of a service with testssl.sh — protocols, ciphers, and "
        "known flaws (Heartbleed, POODLE, ROBOT, weak ciphers). Thorough and slow.",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host"]}),
    "ssh_audit": (
        _b_ssh_audit,
        "Audit an SSH server's configuration with ssh-audit — key exchange, ciphers, "
        "MACs and host-key algorithms, flagging weak/deprecated ones.",
        {"type": "object", "properties": {"host": _H, "port": _PORT},
         "required": ["host"]}),
    "smtp_user_enum": (
        _b_smtp_user_enum,
        "Check whether a username exists on an SMTP server via VRFY/EXPN/RCPT "
        "(smtp-user-enum). Tests one username at a time.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "username": {"type": "string", "description": "Username to test."},
            "method": {"type": "string", "description": "VRFY (default) · EXPN · RCPT."}},
         "required": ["host", "username"]}),
    "wafw00f": (
        _b_wafw00f,
        "Detect and fingerprint a Web Application Firewall in front of a site "
        "(wafw00f).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL."}},
         "required": ["url"]}),
    "git_dump": (
        _b_git_dump,
        "Detect an exposed .git directory on a web server (HEAD/config/logs) — source "
        "code and secrets may be recoverable.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Base site URL, e.g. "
                    "http://10.0.0.5."}},
         "required": ["url"]}),
    "s3_check": (
        _b_s3_check,
        "Check whether an S3 bucket (or a bucket URL) is public and listable, private, "
        "or non-existent.",
        {"type": "object", "properties": {
            "bucket": {"type": "string", "description": "S3 bucket name (tried at "
                       "<name>.s3.amazonaws.com)."},
            "url": {"type": "string", "description": "Or a full bucket URL (any "
                    "provider)."}},
         "required": []}),
    "security_headers": (
        _b_security_headers,
        "Report which HTTP security headers a site sets and which are missing (CSP, "
        "HSTS, X-Frame-Options, …), plus any tech banner.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL."}},
         "required": ["url"]}),
    "cookie_analyze": (
        _b_cookie_analyze,
        "Fetch a page and report each Set-Cookie's flags — Secure, HttpOnly, SameSite "
        "(missing flags are security-relevant).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL."}},
         "required": ["url"]}),
    "favicon_hash": (
        _b_favicon_hash,
        "Fetch a site's favicon and compute its mmh3 hash (Shodan http.favicon.hash) "
        "for fingerprinting/pivoting to other hosts.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Site URL (favicon.ico auto-"
                    "appended) or a direct favicon URL."}},
         "required": ["url"]}),
    "js_endpoints": (
        _b_js_endpoints,
        "Fetch a URL (usually a JavaScript file) and extract the paths, endpoints and "
        "API routes referenced in it.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL of the JS file or page."}},
         "required": ["url"]}),
    "cors_check": (
        _b_cors_check,
        "Test a URL's CORS policy by sending a rogue Origin — flags a reflected origin "
        "and Allow-Credentials:true (exploitable CORS).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL/endpoint."}},
         "required": ["url"]}),
    "dns_bruteforce": (
        _b_dns_bruteforce,
        "Actively resolve a built-in list of common subdomains for a domain (plus any "
        "extra you pass) — complements passive subdomain_enum.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Root domain, e.g. "
                       "example.com."},
            "extra": {"type": "string", "description": "Optional extra subdomains "
                      "(comma/space separated) to also try."}},
         "required": ["domain"]}),
    "bloodhound_python": (
        _b_bloodhound,
        "Collect Active Directory data for BloodHound with bloodhound-python — users, "
        "groups, sessions, ACLs and attack paths. Needs domain credentials or NT hash.",
        {"type": "object", "properties": {
            "dc": {"type": "string", "description": "Domain controller host/IP."},
            "domain": {"type": "string", "description": "AD domain, e.g. corp.local."},
            "collection": {"type": "string", "description": "DCOnly (default) · "
                           "Default · All · Group · Session · ACL · Trusts."},
            "username": _USER, "password": _PASS, "hash": _HASH},
         "required": ["dc", "domain", "username"]}),
    "katana": (
        _b_katana,
        "Crawl a website with katana to map its URLs and endpoints, optionally parsing "
        "JavaScript.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Start URL."},
            "depth": {"type": "integer", "description": "Crawl depth 1-5."},
            "js_crawl": {"type": "boolean", "description": "Also crawl endpoints found "
                         "in JS (-jc)."}},
         "required": ["url"]}),
    "gau": (
        _b_gau,
        "Fetch known URLs for a domain from public sources (Wayback, Common Crawl, OTX) "
        "with gau — passive URL discovery.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain, e.g. example.com."},
            "subs": {"type": "boolean", "description": "Include subdomains."}},
         "required": ["domain"]}),
    "arjun": (
        _b_arjun,
        "Discover hidden HTTP parameters on an endpoint with arjun.",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL/endpoint."},
            "method": {"type": "string", "description": "GET (default) · POST · JSON · "
                       "XML."}},
         "required": ["url"]}),
    "dalfox": (
        _b_dalfox,
        "Scan a URL for XSS with dalfox (params in the URL, POST data or a cookie).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL (with params)."},
            "data": {"type": "string", "description": "POST body to test."},
            "cookie": {"type": "string", "description": "Cookie header."}},
         "required": ["url"]}),
    "commix": (
        _b_commix,
        "Test a URL/parameter for OS command injection with commix (non-interactive).",
        {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL (with params)."},
            "data": {"type": "string", "description": "POST body to test."},
            "cookie": {"type": "string", "description": "Cookie header."}},
         "required": ["url"]}),
    "dnsrecon": (
        _b_dnsrecon,
        "Enumerate a domain's DNS with dnsrecon — standard records, SRV, zone transfer "
        "or reverse lookups.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain, e.g. example.com."},
            "type": {"type": "string", "description": "std (default) · axfr · srv · "
                     "soa · rvl · zonewalk."}},
         "required": ["domain"]}),
    "nbtscan": (
        _b_nbtscan,
        "Scan a host for NetBIOS name information (names, workgroup, MAC) with nbtscan.",
        {"type": "object", "properties": {"host": _H}, "required": ["host"]}),
    "theharvester": (
        _b_theharvester,
        "Gather emails, subdomains and hosts for a domain from OSINT sources with "
        "theHarvester.",
        {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain, e.g. example.com."},
            "source": {"type": "string", "description": "OSINT source (default "
                       "duckduckgo), e.g. bing, crtsh, dnsdumpster."}},
         "required": ["domain"]}),
    "msfvenom": (
        _b_msfvenom,
        "Generate a payload with msfvenom for a listener (text formats only — python, "
        "bash, c, powershell, hex, base64, …). Generated, not executed.",
        {"type": "object", "properties": {
            "payload": {"type": "string", "description": "msf payload, e.g. "
                        "linux/x64/shell_reverse_tcp or cmd/unix/reverse_bash."},
            "lhost": {"type": "string", "description": "Listener IP."},
            "lport": {"type": "integer", "description": "Listener port."},
            "format": {"type": "string", "description": "Output format (default "
                       "python): bash, c, powershell, perl, ruby, hex, base64, …."}},
         "required": ["payload", "lhost", "lport"]}),
    "login_bruteforce": (
        _b_login_bruteforce,
        "Online password attack against ONE service on ONE host with hydra (authorized "
        "testing only). Pick a `service` (ssh/ftp/smb/rdp/mysql/postgres/mssql/vnc/"
        "telnet/http-get/http-post-form), then a single `username`+`password` or a "
        "small preset `userlist`/`passlist`. Bounded and stops on the first hit; keep "
        "lists small to avoid account lockout. Not for the auto enum — a deliberate step.",
        {"type": "object", "properties": {
            "host": _H, "port": _PORT,
            "service": {"type": "string", "description": "Target service: ssh, ftp, "
                        "smb, rdp, mysql, postgres, mssql, vnc, telnet, http-get, "
                        "http-post-form."},
            "username": {"type": "string", "description": "Single username to try."},
            "password": {"type": "string", "description": "Single password to try."},
            "userlist": {"type": "string", "description": "Preset user wordlist: "
                         "common · names (instead of `username`)."},
            "passlist": {"type": "string", "description": "Preset password wordlist: "
                         "common · worst · rockyou (instead of `password`)."},
            "path": {"type": "string", "description": "URL path for http-get (default /)."},
            "form": {"type": "string", "description": "hydra form spec for "
                     "http-post-form, e.g. /login:user=^USER^&pass=^PASS^:F=incorrect."},
            "threads": {"type": "integer", "description": "Parallel tasks 1-16 "
                        "(default 4; keep low to avoid lockout)."}},
         "required": ["host", "service"]}),
    "kerbrute": (
        _b_kerbrute,
        "Kerberos pre-auth abuse against a domain controller with kerbrute: enumerate "
        "valid usernames (userenum), spray one password across users (passwordspray), "
        "or brute one user (bruteuser). Fast and relatively quiet (no failed-logon "
        "events on userenum). Needs a domain and the DC.",
        {"type": "object", "properties": {
            "mode": {"type": "string", "description": "userenum (default) · "
                     "passwordspray · bruteuser."},
            "domain": {"type": "string", "description": "AD domain, e.g. corp.local."},
            "dc": {"type": "string", "description": "Domain controller IP/host."},
            "userlist": {"type": "string", "description": "Preset user wordlist: "
                         "common (default) · names. For userenum/passwordspray."},
            "passlist": {"type": "string", "description": "Preset password wordlist "
                         "for bruteuser: common (default) · worst · rockyou."},
            "username": {"type": "string", "description": "Single user for bruteuser."},
            "password": {"type": "string", "description": "Password to spray "
                         "(passwordspray mode)."}},
         "required": ["domain", "dc"]}),
    "nfs_enum": (
        _b_nfs_enum,
        "List a host's NFS exports with showmount — which directories are shared and to "
        "whom (a * export is world-mountable). Quick unauthenticated foothold check.",
        {"type": "object", "properties": {
            "host": _H,
            "mode": {"type": "string", "description": "exports (-e, default) · all "
                     "(-a, clients+dirs) · dirs (-d, mounted dirs)."}},
         "required": ["host"]}),
    "rsync_enum": (
        _b_rsync_enum,
        "List anonymous rsync modules on a host, or the contents of one module "
        "(rsync --list-only). Exposed modules often allow reading/writing files "
        "without auth.",
        {"type": "object", "properties": {
            "host": _H,
            "port": {"type": "integer", "description": "rsync port (default 873)."},
            "module": {"type": "string", "description": "Module to list (omit to list "
                       "all modules first)."}},
         "required": ["host"]}),
    "memcached_stats": (
        _b_memcached_stats,
        "Query a memcached instance over its text protocol (no auth): version, stats, "
        "item and slab metadata — reveals whether it's exposed and roughly what it "
        "holds. Read-only.",
        {"type": "object", "properties": {
            "host": _H,
            "port": {"type": "integer", "description": "memcached port (default 11211)."}},
         "required": ["host"]}),
    "gpp_decrypt": (
        _b_gpp_decrypt,
        "Decrypt a Group Policy Preferences cpassword (found in SYSVOL Groups.xml, "
        "Services.xml, etc.) back to plaintext using Microsoft's published AES key — a "
        "classic AD credential loot. In-process, no network.",
        {"type": "object", "properties": {
            "cpassword": {"type": "string", "description": "The base64 cpassword value "
                          "from the GPP XML."}},
         "required": ["cpassword"]}),
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
    "sqlmap": (
        "Test for SQL injection and dump data (sqlmap).",
        "SQL injection testing and exploitation with sqlmap: detect injectable "
        "parameters in a URL or POST body, then enumerate databases or dump tables. "
        "Supports cookies and auth. Active/noisy. Keywords: sqlmap, sql injection, "
        "sqli, database dump, --dbs, --dump, union, blind sqli, parameter injection.",
        ["test this url for sql injection", "run sqlmap on the login form",
         "dump the users table via sqli", "enumerate databases with sqlmap",
         "check the id parameter for sqli"]),
    "wpscan": (
        "Scan WordPress for vulns, plugins, users (wpscan).",
        "WordPress security scan with wpscan: enumerate the core version, vulnerable "
        "plugins and themes, and users; an API token adds CVE data. Keywords: wpscan, "
        "wordpress, wp, plugins, themes, users enumeration, cms vulnerability, "
        "wp-content, xmlrpc.",
        ["scan the wordpress site", "enumerate wordpress plugins and users",
         "wpscan for vulnerable plugins", "check this wp site for vulnerabilities"]),
    "enum4linux": (
        "Thorough SMB/Windows enumeration (enum4linux-ng).",
        "Comprehensive SMB/Windows enumeration with enum4linux-ng: OS, domain, users, "
        "groups, shares, password policy and RID cycling — null session or credentials. "
        "Richer than the nmap smb scripts. Keywords: enum4linux, enum4linux-ng, smb, "
        "windows enumeration, users, groups, shares, rid cycling, null session, "
        "port 445, samba.",
        ["run enum4linux on the host", "enumerate windows users and shares",
         "thorough smb enumeration", "enum4linux-ng with these credentials"]),
    "smbmap": (
        "Map SMB share read/write access (smbmap).",
        "SMB share access mapping with smbmap: list shares and show read/write "
        "permissions, optionally recursing the directory tree — null session or "
        "credentials (password or NT hash). Keywords: smbmap, smb shares, share "
        "permissions, read write, recurse, loot, port 445, pass the hash.",
        ["map smb share permissions", "which shares are writable",
         "recurse the smb shares", "smbmap with these creds", "list share access"]),
    "certipy": (
        "Enumerate AD CS / ESC misconfigs (certipy).",
        "Active Directory Certificate Services enumeration with certipy find "
        "-vulnerable: list CAs and certificate templates and flag ESC1-ESC8 "
        "misconfigurations that lead to domain privilege escalation. Needs domain "
        "creds or NT hash. Keywords: certipy, AD CS, adcs, certificate services, ESC1, "
        "ESC8, vulnerable template, domain escalation, pkinit, certificate abuse.",
        ["enumerate AD CS with certipy", "check for vulnerable certificate templates",
         "find ESC misconfigurations", "certipy find vulnerable"]),
    "testssl": (
        "Deep TLS/SSL vulnerability audit (testssl.sh).",
        "Thorough TLS/SSL audit with testssl.sh: enumerate supported protocols and "
        "ciphers and test for known flaws — Heartbleed, POODLE, ROBOT, BEAST, weak "
        "ciphers, cert issues. Slow. Keywords: testssl, ssl audit, tls vulnerabilities, "
        "heartbleed, poodle, robot, weak ciphers, sweet32, cipher suites, port 443.",
        ["run a full ssl audit on 443", "test for heartbleed and poodle",
         "check tls for weak ciphers", "deep testssl scan of the https service"]),
    "ssh_audit": (
        "Audit SSH ciphers/kex/MACs (ssh-audit).",
        "SSH server configuration audit with ssh-audit: report the key-exchange, "
        "cipher, MAC and host-key algorithms and flag weak or deprecated ones, with "
        "CVE notes. Keywords: ssh-audit, ssh hardening, weak ciphers, key exchange, "
        "kex, macs, host key, ssh algorithms, port 22.",
        ["audit the ssh server config", "check ssh for weak ciphers",
         "what ssh algorithms does this server allow", "ssh-audit on port 22"]),
    "smtp_user_enum": (
        "Check if an SMTP username exists (VRFY/EXPN/RCPT).",
        "SMTP user enumeration with smtp-user-enum: check whether a username is valid "
        "on a mail server using VRFY, EXPN or RCPT TO. Keywords: smtp-user-enum, smtp, "
        "vrfy, expn, rcpt, user enumeration, mail server, port 25, valid users.",
        ["check if this user exists over smtp", "smtp vrfy user enumeration",
         "does the mail server accept this username", "enumerate smtp users"]),
    "wafw00f": (
        "Detect a Web Application Firewall (wafw00f).",
        "Web Application Firewall detection with wafw00f: identify whether a WAF sits "
        "in front of a site and fingerprint which one, so you can tune later attacks. "
        "Keywords: wafw00f, waf, web application firewall, cloudflare, akamai, "
        "modsecurity, firewall detection, bypass.",
        ["is there a waf on this site", "detect the web application firewall",
         "fingerprint the waf", "check for cloudflare or modsecurity"]),
    "git_dump": (
        "Detect an exposed .git directory.",
        "Exposed .git detection: fetch /.git/HEAD, config and logs to see whether a "
        "web server leaks its git repository — a common finding that can leak source "
        "code, credentials and history (reconstruct with git-dumper). Keywords: git, "
        ".git exposed, source code leak, git-dumper, dotgit, repository disclosure, "
        "web misconfiguration.",
        ["check for an exposed .git", "is the git directory accessible",
         "look for a .git leak", "detect exposed source repository"]),
    "s3_check": (
        "Check if an S3 bucket is public/listable.",
        "S3 / cloud bucket exposure check: determine whether a bucket is public and "
        "listable (lists objects), private (403) or missing (404). Keywords: s3, "
        "bucket, aws, cloud storage, public bucket, listable, open bucket, object "
        "storage, misconfiguration.",
        ["is this s3 bucket public", "check the bucket for open access",
         "can I list this s3 bucket", "test bucket exposure"]),
    "security_headers": (
        "Check a site's HTTP security headers.",
        "HTTP security-header audit: report which of CSP, HSTS, X-Frame-Options, "
        "X-Content-Type-Options, Referrer-Policy and Permissions-Policy are set or "
        "missing, plus any Server/X-Powered-By tech leak. Keywords: security headers, "
        "CSP, HSTS, x-frame-options, clickjacking, missing headers, hardening, "
        "securityheaders.",
        ["check the security headers", "which security headers are missing",
         "is HSTS and CSP set", "audit the http response headers"]),
    "cookie_analyze": (
        "Check cookie flags (Secure/HttpOnly/SameSite).",
        "Cookie security analysis: fetch a page and report each Set-Cookie's Secure, "
        "HttpOnly and SameSite flags — missing flags enable theft or CSRF. Keywords: "
        "cookies, set-cookie, httponly, secure flag, samesite, session cookie, cookie "
        "security, csrf.",
        ["check the cookie flags", "are the cookies httponly and secure",
         "analyse the session cookie", "does the cookie set samesite"]),
    "favicon_hash": (
        "Compute a favicon's Shodan mmh3 hash.",
        "Favicon hashing: fetch the site's favicon and compute the mmh3 hash Shodan "
        "indexes (http.favicon.hash), to fingerprint the app and pivot to other hosts "
        "running the same one. Keywords: favicon, favicon hash, mmh3, murmurhash, "
        "shodan, fingerprint, pivot, asset discovery.",
        ["get the favicon hash", "compute the shodan favicon hash",
         "fingerprint the app by its favicon", "favicon mmh3 for pivoting"]),
    "js_endpoints": (
        "Extract endpoints/paths from a JS file.",
        "JavaScript endpoint extraction: fetch a JS file (or page) and pull out the "
        "paths, API routes and URLs referenced in it — surfaces hidden endpoints for "
        "further testing. Keywords: js, javascript, endpoints, api routes, linkfinder, "
        "hidden endpoints, url extraction, secrets in js, paths.",
        ["extract endpoints from this js file", "find api routes in the javascript",
         "pull paths out of the js", "what endpoints does this script reference"]),
    "cors_check": (
        "Test for a misconfigured CORS policy.",
        "CORS misconfiguration test: send a rogue Origin and check whether the server "
        "reflects it in Access-Control-Allow-Origin, especially with Allow-"
        "Credentials:true (exploitable — cross-origin data theft). Keywords: cors, "
        "access-control-allow-origin, allow-credentials, origin reflection, cross-"
        "origin, misconfiguration.",
        ["check for a cors misconfiguration", "does the api reflect the origin",
         "test cors on this endpoint", "is cors exploitable here"]),
    "dns_bruteforce": (
        "Actively brute common subdomains (built-in list).",
        "Active subdomain discovery: resolve a built-in list of common subdomains "
        "(www, mail, dev, api, vpn, admin…) plus any extras against a domain — finds "
        "hosts passive OSINT misses. Keywords: subdomain brute force, dns brute, "
        "subdomains, resolve, dnsrecon, gobuster dns, active enumeration, hostnames.",
        ["brute force subdomains of example.com", "find subdomains by resolving common names",
         "active subdomain discovery", "resolve common subdomains for the domain"]),
    "bloodhound_python": (
        "Collect AD data for BloodHound (attack paths).",
        "Active Directory collection for BloodHound with bloodhound-python: gather "
        "users, groups, sessions, ACLs and trusts to map privilege-escalation and "
        "lateral-movement paths. Needs domain creds or NT hash. Keywords: bloodhound, "
        "sharphound, AD, attack path, ACL, sessions, domain admin, lateral movement, "
        "graph, collector, active directory.",
        ["collect bloodhound data for the domain", "run sharphound/bloodhound-python",
         "map AD attack paths", "gather active directory data with these creds"]),
    "katana": (
        "Crawl a website for URLs/endpoints (katana).",
        "Web crawling with katana: map a site's URLs, forms and endpoints, optionally "
        "following JavaScript, to build the attack surface. Keywords: katana, crawler, "
        "spider, urls, endpoints, web crawling, js crawl, attack surface, links.",
        ["crawl the website for urls", "map the site's endpoints",
         "spider the web app", "katana crawl including javascript"]),
    "gau": (
        "Fetch known URLs from Wayback/OTX (gau).",
        "Passive URL discovery with gau (getallurls): pull historically known URLs for "
        "a domain from the Wayback Machine, Common Crawl and OTX — reveals old and "
        "hidden endpoints without touching the target. Keywords: gau, getallurls, "
        "wayback, common crawl, otx, urls, passive, historical endpoints, archive.",
        ["get known urls for the domain", "fetch wayback urls",
         "passive url discovery with gau", "find historical endpoints"]),
    "arjun": (
        "Discover hidden HTTP parameters (arjun).",
        "HTTP parameter discovery with arjun: find hidden or undocumented GET/POST/JSON "
        "parameters an endpoint accepts — widens the injection/testing surface. "
        "Keywords: arjun, parameter discovery, hidden parameters, param mining, GET, "
        "POST, fuzzing parameters, api params.",
        ["find hidden parameters on this endpoint", "discover http params with arjun",
         "mine parameters for the api", "what parameters does this url accept"]),
    "dalfox": (
        "Scan a URL for XSS (dalfox).",
        "XSS scanning with dalfox: test URL parameters, POST data or a cookie for "
        "reflected/stored cross-site scripting and report working payloads. Keywords: "
        "dalfox, xss, cross-site scripting, reflected xss, dom xss, payload, injection, "
        "web vulnerability.",
        ["scan this url for xss", "test the parameter for cross-site scripting",
         "run dalfox on the endpoint", "check for reflected xss"]),
    "commix": (
        "Test for OS command injection (commix).",
        "Command-injection testing with commix: detect and exploit OS command injection "
        "in a URL parameter, POST body or cookie (non-interactive). Keywords: commix, "
        "command injection, os command, rce, shell injection, cmdi, exploitation.",
        ["test this url for command injection", "check the param for os command injection",
         "run commix on the endpoint", "is there command injection here"]),
    "dnsrecon": (
        "Enumerate DNS records / zone transfer (dnsrecon).",
        "DNS enumeration with dnsrecon: standard records, SRV services, zone transfer "
        "(AXFR), reverse lookups and zone walking for a domain. Keywords: dnsrecon, dns "
        "enumeration, records, srv, axfr, zone transfer, reverse dns, zone walk, "
        "nameserver.",
        ["enumerate dns records for the domain", "run dnsrecon",
         "try a dns zone transfer with dnsrecon", "list srv records"]),
    "nbtscan": (
        "Scan a host for NetBIOS names (nbtscan).",
        "NetBIOS name scan with nbtscan: pull NetBIOS names, workgroup/domain and MAC "
        "from a host over UDP/137. Keywords: nbtscan, netbios, nbt, workgroup, port 137, "
        "windows name, mac address, smb host.",
        ["nbtscan the host", "get the netbios name", "what workgroup is this host in",
         "netbios enumeration"]),
    "theharvester": (
        "OSINT emails/subdomains/hosts (theHarvester).",
        "OSINT gathering with theHarvester: collect emails, subdomains, hostnames and "
        "IPs for a domain from public search engines and data sources — no traffic to "
        "the target. Keywords: theharvester, osint, emails, subdomains, reconnaissance, "
        "footprinting, employees, hosts, passive recon.",
        ["harvest emails for the domain", "osint recon with theharvester",
         "find subdomains and emails", "gather public info about the company"]),
    "msfvenom": (
        "Generate a Metasploit payload (msfvenom).",
        "Payload generation with msfvenom: build a reverse/bind payload for a listener "
        "in a text format (python, bash, c, powershell, hex, base64…). Generated only, "
        "never executed. Keywords: msfvenom, metasploit, payload, shellcode, reverse "
        "shell, staged, encoder, generate payload, LHOST, LPORT.",
        ["generate a msfvenom reverse shell payload", "build a python payload with msfvenom",
         "create shellcode for this listener", "msfvenom powershell payload"]),
    "login_bruteforce": (
        "Online password brute-force / spray against a service (hydra).",
        "Online password guessing with hydra against one service on one host: ssh, ftp, "
        "smb, rdp, mysql, postgres, mssql, vnc, telnet, http basic-auth or an http POST "
        "login form. Try a single credential or small preset user/password wordlists; "
        "bounded, stops on first success. Authorized testing only — keep lists small to "
        "avoid account lockout. Keywords: hydra, brute force, password spray, credential "
        "attack, dictionary attack, ssh brute, ftp brute, rdp, weak password, login form.",
        ["brute force ssh on 10.0.0.5", "try common passwords against the ftp login",
         "password spray the rdp service", "hydra attack the mysql login",
         "guess the admin password on the web login form"]),
    "kerbrute": (
        "Kerberos username enumeration and password spray (kerbrute).",
        "Kerberos pre-authentication abuse with kerbrute against a domain controller: "
        "enumerate valid AD usernames without logging failures (userenum), spray one "
        "password across many users (passwordspray), or brute a single user (bruteuser). "
        "Fast Active Directory attack. Keywords: kerbrute, kerberos, AS-REP, user "
        "enumeration, password spraying, active directory, domain controller, valid "
        "usernames, pre-auth.",
        ["enumerate valid AD usernames", "kerberos user enumeration on the domain",
         "password spray active directory", "find valid users on the domain controller",
         "spray Winter2024 across the users"]),
    "nfs_enum": (
        "List a host's NFS exports (showmount).",
        "NFS share enumeration with showmount: list the exported directories and which "
        "clients may mount them — a world-mountable (*) export is an unauthenticated "
        "read/write foothold. Keywords: nfs, showmount, exports, port 2049, mountd, "
        "network file system, no_root_squash, share.",
        ["list nfs exports on 10.0.0.5", "showmount the target",
         "what nfs shares are exported", "check for world-mountable nfs"]),
    "rsync_enum": (
        "List anonymous rsync modules or their contents.",
        "rsync module enumeration with rsync --list-only: list the anonymous rsync "
        "modules a host exposes, then read a module's file listing — exposed modules "
        "often allow unauthenticated file read or write. Keywords: rsync, port 873, "
        "rsync module, anonymous rsync, file sync, list-only, backup share.",
        ["list rsync modules on 10.0.0.5", "enumerate rsync on port 873",
         "what does the rsync share contain", "check anonymous rsync access"]),
    "memcached_stats": (
        "Read an exposed memcached's stats and metadata.",
        "memcached enumeration over the text protocol (no auth): pull version, stats, "
        "item and slab metadata to confirm exposure and gauge cached data. Keywords: "
        "memcached, port 11211, stats items, cache, unauthenticated, key-value store, "
        "data exposure.",
        ["check memcached on 10.0.0.5", "dump memcached stats",
         "is memcached exposed on 11211", "enumerate the memcached instance"]),
    "gpp_decrypt": (
        "Decrypt a GPP cpassword to plaintext.",
        "Group Policy Preferences cpassword decryption: reverse a cpassword value from "
        "SYSVOL Groups.xml / Services.xml / ScheduledTasks.xml using Microsoft's "
        "published AES-256 key, recovering a stored domain credential. In-process, no "
        "network. Keywords: GPP, cpassword, Groups.xml, SYSVOL, MS14-025, group policy "
        "preferences, decrypt password, active directory credential loot.",
        ["decrypt this gpp cpassword", "recover the password from Groups.xml",
         "decode a SYSVOL cpassword", "crack the group policy preferences password"]),
}

# Suggested wait budget (seconds) per tool — advertised in tools/list so the agent
# knows how long each may take (a fast scan finishes early; a full/vuln scan needs
# minutes). The SERVER does not enforce it — the client uses it to decide how long to
# wait and kills the call if exceeded. Tools not listed use _DEFAULT_TOOL_TIMEOUT.
_DEFAULT_TOOL_TIMEOUT = 120
_TIMEOUTS = {
    # instant, in-process (python-native)
    "hash_identify": 15, "jwt_decode": 15, "data_transform": 15, "cidr_expand": 15,
    "ip_info": 15, "payload_gen": 15, "default_creds": 15, "cve_lookup": 30,
    "tls_analyze": 30, "robots_sitemap": 60,
    # fast network
    "dns_lookup": 60, "whois": 60, "http_headers": 60, "http_request": 60,
    "banner_grab": 90, "ftp_anon": 90, "ssl_cert": 90, "dns_zone_transfer": 60,
    "redis_cli": 60, "mongo_query": 90, "searchsploit": 60,
    # medium
    "service_discovery": 300, "smb_enum": 180, "snmp_walk": 120, "ldap_search": 120,
    "rpc_enum": 120, "smb_client": 120, "netexec_smb": 300, "mysql_query": 120,
    "mssql_query": 120, "psql_query": 120, "ssh_exec": 120, "winrm_exec": 120,
    "ftp_transfer": 120, "impacket_exec": 300, "kerberos_roast": 300,
    "secretsdump": 600, "enum4linux": 300, "smbmap": 180, "certipy": 300,
    "ssh_audit": 120, "smtp_user_enum": 120, "wafw00f": 120, "traceroute": 120,
    "whatweb": 120,
    # heavy scanners
    "port_discovery": 900, "script_scan": 600, "nuclei_scan": 900, "nikto_scan": 900,
    "sqlmap": 900, "testssl": 900, "wpscan": 600, "web_content_discovery": 600,
    "vhost_fuzz": 600, "subdomain_enum": 300,
    # batch 6 python-native web/recon (network I/O)
    "git_dump": 30, "s3_check": 30, "security_headers": 20, "cookie_analyze": 20,
    "favicon_hash": 20, "js_endpoints": 30, "cors_check": 20, "dns_bruteforce": 90,
    # batch 7 CLI
    "bloodhound_python": 600, "katana": 300, "gau": 120, "arjun": 300, "dalfox": 600,
    "commix": 600, "dnsrecon": 300, "nbtscan": 60, "theharvester": 300, "msfvenom": 60,
    # batch 8 credential attacks + service gaps
    "login_bruteforce": 900, "kerbrute": 600, "nfs_enum": 90, "rsync_enum": 120,
    "memcached_stats": 30, "gpp_decrypt": 15,
}

# The external program each tool needs on PATH (None = python-native, always runnable).
# Advertised in tools/list as `requires` so a client can report which tools are usable
# and which need a program installed (purragent's /doctor). For tools whose exact binary
# depends on a mode/method (impacket exec/roast) the representative one is listed — they
# ship in the same package. `ssh_exec` also needs `sshpass` for password auth.
_REQUIRES = {
    "port_discovery": "nmap", "service_discovery": "nmap", "script_scan": "nmap",
    "smb_enum": "nmap", "ssl_cert": "nmap", "ftp_anon": "nmap", "banner_grab": "nmap",
    "http_headers": "curl", "http_request": "curl", "ftp_transfer": "curl",
    "dns_lookup": "dig", "dns_zone_transfer": "dig", "snmp_walk": "snmpwalk",
    "searchsploit": "searchsploit", "whois": "whois", "ldap_search": "ldapsearch",
    "rpc_enum": "rpcclient", "secretsdump": "impacket-secretsdump",
    "impacket_exec": "impacket-wmiexec", "kerberos_roast": "impacket-GetUserSPNs",
    "mysql_query": "mysql", "mssql_query": "nxc", "psql_query": "psql",
    "redis_cli": "redis-cli", "mongo_query": "mongosh", "ssh_exec": "ssh",
    "winrm_exec": "nxc", "netexec_smb": "nxc", "smb_client": "smbclient",
    "smbmap": "smbmap", "enum4linux": "enum4linux-ng", "certipy": "certipy",
    "bloodhound_python": "bloodhound-python", "kerbrute": "kerbrute",
    "nfs_enum": "showmount", "rsync_enum": "rsync", "nikto_scan": "nikto",
    "nuclei_scan": "nuclei", "sqlmap": "sqlmap", "wpscan": "wpscan",
    "testssl": "testssl", "web_content_discovery": "ffuf", "vhost_fuzz": "ffuf",
    "subdomain_enum": "subfinder", "katana": "katana", "gau": "gau", "arjun": "arjun",
    "dalfox": "dalfox", "commix": "commix", "dnsrecon": "dnsrecon", "nbtscan": "nbtscan",
    "theharvester": "theHarvester", "msfvenom": "msfvenom", "ssh_audit": "ssh-audit",
    "smtp_user_enum": "smtp-user-enum", "wafw00f": "wafw00f", "traceroute": "traceroute",
    "whatweb": "whatweb", "login_bruteforce": "hydra",
}

# Python libraries a python-native tool needs. Each entry is a list of groups; a group is
# a tuple (import-name alternatives, pip hint) satisfied if ANY of its modules imports.
# Checked SERVER-SIDE (this process's own env, which is where the tool runs) and the
# unsatisfied groups' hints are advertised as `py_missing` in tools/list, so /doctor can
# flag a native tool whose library is absent (most native tools are stdlib-only).
_PY_REQUIRES = {
    "gpp_decrypt": [(("Crypto", "cryptography"), "pip: pycryptodome")],
}


# ── authenticated loot tools (registered after the tables above) ──────────────
# read_file / flag_hunt dispatch to ssh/winrm/smb/ftp by `service`, so no single binary
# is advertised (the runner reports [not installed] for whichever one a call needs).
_KEYFILE = {"type": "string", "description": "Path to an SSH private key (instead of a "
            "password), for service=ssh."}
HACKTOOLS["read_file"] = (
    _b_read_file,
    "Read ONE file off a host over an authenticated service (ssh/winrm/smb/ftp) with "
    "recovered credentials — e.g. cat a known flag or config path. Read-only.",
    {"type": "object", "properties": {
        "host": _H, "port": _PORT,
        "service": {"type": "string", "description": "ssh · winrm · smb · ftp — the "
                    "authenticated service to read the file over."},
        "path": {"type": "string", "description": "Path of the file to read (e.g. "
                 "/root/root.txt, or a share-relative path for smb)."},
        "share": {"type": "string", "description": "SMB share the path is on "
                  "(service=smb)."},
        "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN,
        "key": _KEYFILE},
     "required": ["host", "service", "path"]})
HACKTOOLS["flag_hunt"] = (
    _b_flag_hunt,
    "Hunt for a flag on a host: with a validated shell login (ssh on Linux, winrm on "
    "Windows) sweep the usual flag/secret locations (/root, /home/*, Desktop, user.txt/"
    "root.txt/flag*, …) and return what's found. Read-only, one login.",
    {"type": "object", "properties": {
        "host": _H, "port": _PORT,
        "service": {"type": "string", "description": "ssh (Linux) · winrm (Windows) — "
                    "the shell service to sweep the filesystem over."},
        "username": _USER, "password": _PASS, "hash": _HASH, "domain": _DOMAIN,
        "key": _KEYFILE},
     "required": ["host", "service"]})

_META["read_file"] = (
    "Read a file over ssh/winrm/smb/ftp with creds.",
    "Authenticated file read: pull a single file off a host over ssh (cat), winrm "
    "(Get-Content), smb (smbclient get) or ftp (curl), using recovered credentials. "
    "Read-only loot of a KNOWN path. Keywords: read file, cat, get-content, download, "
    "loot, flag, user.txt, root.txt, config, credentials, post-exploitation, smb get.",
    ["read /root/root.txt over ssh with these creds",
     "cat user.txt from the box using the password",
     "grab C:\\Users\\bob\\Desktop\\user.txt over winrm",
     "download config.php from the smb share",
     "read the flag file with the recovered login"])
_META["flag_hunt"] = (
    "Sweep the usual paths for a flag using a login.",
    "Flag hunt: with a validated shell login (ssh/winrm) sweep the common flag and "
    "secret locations across the filesystem and return what's found — the fast way to "
    "capture a flag once you have credentials. Read-only. Keywords: flag, capture the "
    "flag, ctf, user.txt, root.txt, proof.txt, loot, find flag, HTB, search filesystem, "
    "post-exploitation, foothold, privilege.",
    ["hunt for the flag over ssh with these creds",
     "find the flag on the box using the password",
     "sweep for user.txt and root.txt over winrm",
     "look for a flag now that I have a login",
     "search the filesystem for the flag"])

_TIMEOUTS["read_file"] = 90
_TIMEOUTS["flag_hunt"] = 180


__all__ = ['HACKTOOLS', '_META', '_DEFAULT_TOOL_TIMEOUT', '_TIMEOUTS', '_REQUIRES', '_PY_REQUIRES']

