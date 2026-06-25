"""
output_parser.py — extracts Findings, Targets and Ports from terminal command output.

Priority 1  Global regex — zero / near-zero false positives on any output.
Priority 2  Tool-specific parsers — low FP when the producing tool is known.
Priority 3  (planned) Moderate-FP patterns with additional context filtering.

Usage:
    parser = OutputParser()
    parser.process(db=db, cmd_id=cid, cmd="nmap -sV 10.10.10.1", output="...", tags=["recon"])
"""
from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# ANSI stripping
# ---------------------------------------------------------------------------

_RE_ANSI = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


def _strip_ansi(text: str) -> str:
    return _RE_ANSI.sub('', text)


def _valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    return (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    )


def _get_line(text: str, pos: int) -> str:
    """Return the full line that contains character position pos."""
    start = text.rfind('\n', 0, pos) + 1
    end   = text.find('\n', pos)
    return text[start:(end if end != -1 else len(text))]


# ---------------------------------------------------------------------------
# Priority 1 — Global patterns (tool-independent)
# ---------------------------------------------------------------------------

# CVE identifiers
_RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')

# Kerberoasting TGS  (hashcat -m 13100)
_RE_KRB5TGS = re.compile(
    r'\$krb5tgs\$\d+\$\*[^*]+\*\$[A-Fa-f0-9$]+'
)

# AS-REP Roasting  (hashcat -m 18200)
_RE_KRB5ASREP = re.compile(
    r'\$krb5asrep\$\d+\$[^:]+:[A-Fa-f0-9]+\$[A-Fa-f0-9]+'
)

# secretsdump NTLM  user:RID:LM:NT:::
_RE_NTLM = re.compile(
    r'^([^:\n]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$',
    re.MULTILINE,
)

# CTF flags — strict whitelist of well-known platform prefixes
_RE_CTF = re.compile(
    r'\b('
    r'HTB\{[^}]+\}'
    r'|THM\{[^}]+\}'
    r'|picoCTF\{[^}]+\}'
    r'|FLAG\{[^}]+\}'
    r'|flag\{[^}]+\}'
    r'|CTF\{[^}]+\}'
    r'|DUCTF\{[^}]+\}'
    r'|PCTF\{[^}]+\}'
    r'|HV\{[^}]+\}'
    r')'
)

# Hydra successful login
# [22][ssh] host: 10.10.10.5   login: root   password: toor
_RE_HYDRA = re.compile(
    r'^\[(\d+)\]\[([^\]]+)\]\s+host:\s*([\d.]+)\s+'
    r'login:\s*(\S*)\s+password:\s*(.*)$',
    re.MULTILINE,
)

# Medusa successful login
# ACCOUNT FOUND: [ssh] Host: 10.10.10.5 User: root Password: toor [SUCCESS]
_RE_MEDUSA = re.compile(
    r'^ACCOUNT FOUND:\s+\[([^\]]+)\]\s+Host:\s*([\d.]+)\s+'
    r'User:\s*(\S+)\s+Password:\s*(\S*)\s+\[SUCCESS\]$',
    re.MULTILINE,
)

# Ncrack discovered credentials
#   10.10.10.5 22/tcp ssh: 'root' 'toor'
_RE_NCRACK = re.compile(
    r'^\s+([\d.]+)\s+(\d{1,5})/(tcp|udp)\s+(\S+):\s+'
    r"'([^']*)'\s+'([^']*)'",
    re.MULTILINE,
)

# kerbrute valid username / password
# [+] VALID USERNAME:  jsmith@corp.local
# [+] VALID PASSWORD:  jsmith@corp.local:Password123
_RE_KERBRUTE_USER = re.compile(
    r'\[\+\] VALID USERNAME:\s+([A-Za-z0-9._-]+@[A-Za-z0-9.-]+)',
    re.MULTILINE,
)
_RE_KERBRUTE_PASS = re.compile(
    r'\[\+\] VALID PASSWORD:\s+([A-Za-z0-9._-]+@[A-Za-z0-9.-]+):(.+)$',
    re.MULTILINE,
)

# rpcclient / enum4linux users
# user:[Administrator] rid:[0x1f4]
_RE_RPCCLIENT_USER = re.compile(
    r'^user:\[([^\]]+)\] rid:\[(0x[0-9a-fA-F]+|\d+)\]$',
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Priority 2 — Tool-specific patterns
# ---------------------------------------------------------------------------

# nmap — host header
# Nmap scan report for forest.htb (10.10.10.161)
# Nmap scan report for 10.10.10.161
_RE_NMAP_HOST = re.compile(
    r'^Nmap scan report for (?:(\S+) \()?([\d.]+)\)?',
    re.MULTILINE,
)

# nmap — port / service / version line
# 88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
_RE_NMAP_PORT = re.compile(
    r'^(\d{1,5})/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?$',
    re.MULTILINE,
)

# masscan
# Discovered open port 445/tcp on 10.10.10.161
_RE_MASSCAN = re.compile(
    r'^Discovered open port (\d{1,5})/(tcp|udp) on ([\d.]+)$',
    re.MULTILINE,
)

# rustscan
# Open 10.10.10.161:80
_RE_RUSTSCAN = re.compile(
    r'^Open ([\d.]+):(\d{1,5})$',
    re.MULTILINE,
)

# netexec / nxc / crackmapexec — host info line  [*]
# SMB  10.10.10.5  445  DC01  [*] Windows Server 2016 (name:DC01)(domain:htb.local)
_RE_NXC_HOST = re.compile(
    r'^(SMB|LDAP|RDP|WINRM|MSSQL|SSH|FTP|WMI)\s+'
    r'([\d.]+)\s+(\d{1,5})\s+(\S+)\s+'
    r'\[\*\]\s+(.+)$',
    re.MULTILINE,
)

# netexec / nxc / crackmapexec — auth success line  [+]
# SMB  10.10.10.5  445  DC01  [+] CORP\admin:Password123 (Pwn3d!)
_RE_NXC_AUTH = re.compile(
    r'^(SMB|LDAP|RDP|WINRM|MSSQL|SSH|FTP|WMI)\s+'
    r'([\d.]+)\s+\d+\s+\S+\s+'
    r'\[\+\]\s+(\S+)\\(\S+):(\S+)',
    re.MULTILINE,
)

# netexec / nxc — SAM/NTDS dump line (secretsdump format after nxc prefix)
# SMB  10.10.10.5  445  DC01  Administrator:500:aad3...:31d6...:::
_RE_NXC_SAM = re.compile(
    r'^(?:SMB|LDAP|WMI)\s+[\d.]+\s+\d+\s+\S+\s+'
    r'([^:\s]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$',
    re.MULTILINE,
)

# nuclei finding line
# [CVE-2021-44228] [http] [critical] https://target.com/endpoint
_RE_NUCLEI = re.compile(
    r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+'
    r'\[(critical|high|medium|low|info|unknown)\]\s+'
    r'(https?://\S+|[\w.-]+:\d+)'
    r'(?:\s+\[([^\]]+)\])?$',
    re.MULTILINE,
)

# feroxbuster
# 200  GET  147l  510w  9301c  https://target.htb/admin
_RE_FEROX = re.compile(
    r'^(\d{3})\s+(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+'
    r'\d+l\s+\d+w\s+\d+c\s+(https?://\S+)',
    re.MULTILINE,
)

# gobuster
# /admin   (Status: 200) [Size: 1234]
_RE_GOBUSTER = re.compile(
    r'^(/\S*)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?',
    re.MULTILINE,
)

# ffuf
# admin   [Status: 200, Size: 1234, Words: 510, Lines: 147, Duration: 15ms]
_RE_FFUF = re.compile(
    r'^(\S+)\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+),\s*Words:\s*\d+',
    re.MULTILINE,
)

# nikto OSVDB finding
# + OSVDB-3092: /admin/: Admin directory found
_RE_NIKTO_OSVDB = re.compile(
    r'^\+ OSVDB-(\d+):\s+(/[^:]*)?:\s*(.+)$',
    re.MULTILINE,
)

# nikto server banner
# + Server: Apache/2.4.41 (Ubuntu)
_RE_NIKTO_SERVER = re.compile(
    r'^\+ Server:\s+(.+)$',
    re.MULTILINE,
)

# arp-scan
# 192.168.1.1   00:50:56:c0:00:08   VMware, Inc.
_RE_ARPSCAN = re.compile(
    r'^([\d.]+)\t([0-9a-f:]{17})\t(.+)$',
    re.MULTILINE,
)

# netexec / nxc — Pwn3d! indicator (local admin confirmed)
_RE_NXC_PWND = re.compile(r'\(Pwn3d!\)', re.IGNORECASE)

# john the ripper — cracked password line
# password123      (admin)
# password123      (admin:0)   ← --format=NT style
_RE_JOHN_CRACKED = re.compile(
    r'^(.+?)\s{2,}\(([^:)]+)(?::\d+)?\)\s*$',
    re.MULTILINE,
)
_JOHN_SKIP_PREFIXES = (
    'Using ', 'Loaded ', 'Warning:', 'Press ', 'Session ', 'Proceeding',
    'No password', 'Remaining', 'guesses:', 'Will run',
)

# hashcat — cracked hash:plaintext (end-of-session output or --show)
_RE_HASHCAT_CRACKED = re.compile(
    r'^([0-9a-fA-F]{32,64}):(.+)$',
    re.MULTILINE,
)

# enum4linux — share enumeration table
#         print$          Disk      Printer Drivers
_RE_ENUM4LINUX_SHARE = re.compile(
    r'^\s{2,}(\w[\w$]*)\s{2,}(Disk|IPC|Printer)\s*(.*?)$',
    re.MULTILINE,
)

# smbmap — target header
# [+] IP: 10.10.10.5:445  Name: dc01.htb.local
_RE_SMBMAP_HOST = re.compile(
    r'\[\+\]\s+IP:\s*([\d.]+):\d+\s+Name:\s*(\S+)',
    re.MULTILINE,
)

# smbmap — share with accessible permissions (tab-indented rows)
#	data	READ, WRITE
#	print$	READ ONLY	Printer Drivers
_RE_SMBMAP_SHARE = re.compile(
    r'^\t(\w[\w$]+)\s+(READ ONLY|READ,\s*WRITE|WRITE ONLY|READ)\s*(.*?)$',
    re.MULTILINE,
)

# sqlmap — injectable parameter
# [INFO] GET parameter 'id' is vulnerable
# [INFO] parameter 'id' appears to be 'boolean-based blind' injectable
_RE_SQLMAP_VULN = re.compile(
    r"parameter ['\"]?(\w+)['\"]? (?:appears to be|is) (?:dynamic and )?(?:injectable|vulnerable)",
    re.IGNORECASE,
)
# sqlmap — detected DBMS
# [INFO] the back-end DBMS is MySQL
_RE_SQLMAP_DBMS = re.compile(
    r'back-end DBMS is ([A-Za-z][A-Za-z0-9 ]{2,20})',
    re.IGNORECASE,
)

# evil-winrm — active shell prompt
# *Evil-WinRM* PS C:\Users\Administrator\Documents>
_RE_EVILWINRM = re.compile(
    r'\*Evil-WinRM\*\s+PS\s+([A-Za-z]:\\[^\s>]*)',
    re.MULTILINE,
)

# wpscan — outdated / insecure WordPress version
# [+] WordPress version 5.7.2 identified (Insecure, released on 2021-04-01).
_RE_WPSCAN_WP_VER = re.compile(
    r'\[\+\]\s+WordPress version ([\d.]+) identified \(Insecure',
    re.IGNORECASE,
)
# wpscan — plugin / theme vulnerability title
#  | [!] Title: Vulnerable Plugin <= 1.5 - SQL Injection
_RE_WPSCAN_PLUGIN_VULN = re.compile(
    r'\[!\]\s+Title:\s+(.+)$',
    re.MULTILINE,
)
# wpscan — "User(s) Identified:" section, then [+] username lines
_RE_WPSCAN_USERS_HDR = re.compile(
    r'User\(s\) Identified:(.*?)(?=\n\s*\[(?:i\]|\+\]|!\])|\Z)',
    re.DOTALL | re.IGNORECASE,
)
_RE_WPSCAN_USER_LINE = re.compile(
    r'^\s*\[\+\]\s+([\w.\-]+)\s*$',
    re.MULTILINE,
)

# Interesting HTTP statuses for web path findings
_WEB_INTERESTING = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}

# Tool name → which Priority-2 parser method to call
_TOOL_PARSERS = {
    'nmap':          '_parse_nmap',
    'masscan':       '_parse_masscan',
    'rustscan':      '_parse_rustscan',
    'netexec':       '_parse_nxc',
    'nxc':           '_parse_nxc',
    'crackmapexec':  '_parse_nxc',
    'nuclei':        '_parse_nuclei',
    'feroxbuster':   '_parse_feroxbuster',
    'gobuster':      '_parse_gobuster',
    'ffuf':          '_parse_ffuf',
    'nikto':         '_parse_nikto',
    'arp-scan':      '_parse_arpscan',
    'john':          '_parse_john',
    'hashcat':       '_parse_hashcat',
    'enum4linux':    '_parse_enum4linux',
    'enum4linux-ng': '_parse_enum4linux',
    'smbmap':        '_parse_smbmap',
    'sqlmap':        '_parse_sqlmap',
    'evil-winrm':    '_parse_evilwinrm',
    'wpscan':        '_parse_wpscan',
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class OutputParser:
    """
    Parses terminal command output and writes Findings / Targets / Ports to DB.
    Call process() after every insert_command() + add_tags().
    """

    def process(
        self,
        db,
        cmd_id: int,
        cmd: str,
        output: Optional[str],
        tags: list,
    ) -> None:
        if not output or not output.strip():
            return
        clean = _strip_ansi(output)
        seen: set = set()

        self._parse_priority1(db, cmd_id, clean, seen)

        tool = cmd.strip().split()[0] if cmd.strip() else ''
        method_name = _TOOL_PARSERS.get(tool)
        if method_name:
            getattr(self, method_name)(db, cmd_id, cmd, clean, seen)

    # -----------------------------------------------------------------------
    # Priority 1 — global patterns
    # -----------------------------------------------------------------------

    def _parse_priority1(self, db, cmd_id: int, output: str, seen: set) -> None:

        # CVE
        for m in _RE_CVE.finditer(output):
            val = m.group(0)
            if ('cve', val) not in seen:
                seen.add(('cve', val))
                db.add_finding(
                    finding_type='cve',
                    value=val,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=_get_line(output, m.start()),
                )

        # Kerberoasting TGS
        for m in _RE_KRB5TGS.finditer(output):
            val = m.group(0)
            if ('hash', val[:60]) not in seen:
                seen.add(('hash', val[:60]))
                db.add_finding(
                    finding_type='hash',
                    value=val,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=_get_line(output, m.start()),
                    notes='kerberoasting TGS  hashcat -m 13100',
                )

        # AS-REP Roasting
        for m in _RE_KRB5ASREP.finditer(output):
            val = m.group(0)
            if ('hash', val[:60]) not in seen:
                seen.add(('hash', val[:60]))
                db.add_finding(
                    finding_type='hash',
                    value=val,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=_get_line(output, m.start()),
                    notes='ASREProasting AS-REP  hashcat -m 18200',
                )

        # NTLM secretsdump format
        for m in _RE_NTLM.finditer(output):
            username, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
            val = m.group(0)
            if ('hash', username.lower(), nt) not in seen:
                seen.add(('hash', username.lower(), nt))
                db.add_finding(
                    finding_type='hash',
                    value=val,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=val,
                    notes=f'NTLM  user:{username}  NT:{nt}',
                )

        # CTF flags
        for m in _RE_CTF.finditer(output):
            val = m.group(0)
            if ('flag', val) not in seen:
                seen.add(('flag', val))
                db.add_finding(
                    finding_type='flag',
                    value=val,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=_get_line(output, m.start()),
                )

        # Hydra credentials
        for m in _RE_HYDRA.finditer(output):
            port, svc, ip, user, pwd = (
                m.group(1), m.group(2), m.group(3),
                m.group(4), m.group(5).strip(),
            )
            if not _valid_ip(ip):
                continue
            if ('cred', ip, user, svc) not in seen:
                seen.add(('cred', ip, user, svc))
                db.add_finding(
                    finding_type='credential',
                    value=f'{user}:{pwd}',
                    command_id=cmd_id,
                    target=ip,
                    port=int(port),
                    service=svc,
                    confidence=1.0,
                    raw_line=m.group(0),
                    notes=f'hydra  {svc}://{ip}:{port}  login:{user}',
                )

        # Medusa credentials
        for m in _RE_MEDUSA.finditer(output):
            svc, ip, user, pwd = m.group(1), m.group(2), m.group(3), m.group(4)
            if not _valid_ip(ip):
                continue
            if ('cred', ip, user, svc) not in seen:
                seen.add(('cred', ip, user, svc))
                db.add_finding(
                    finding_type='credential',
                    value=f'{user}:{pwd}',
                    command_id=cmd_id,
                    target=ip,
                    service=svc,
                    confidence=1.0,
                    raw_line=m.group(0),
                    notes=f'medusa  {svc}://{ip}  login:{user}',
                )

        # Ncrack credentials
        for m in _RE_NCRACK.finditer(output):
            ip, port, proto, svc, user, pwd = (
                m.group(1), m.group(2), m.group(3),
                m.group(4), m.group(5), m.group(6),
            )
            if not _valid_ip(ip):
                continue
            if ('cred', ip, user, svc) not in seen:
                seen.add(('cred', ip, user, svc))
                db.add_finding(
                    finding_type='credential',
                    value=f'{user}:{pwd}',
                    command_id=cmd_id,
                    target=ip,
                    port=int(port),
                    service=svc,
                    confidence=1.0,
                    raw_line=m.group(0),
                    notes=f'ncrack  {svc}://{ip}:{port}  login:{user}',
                )

        # kerbrute — valid username
        for m in _RE_KERBRUTE_USER.finditer(output):
            upn = m.group(1)
            if ('user', upn) not in seen:
                seen.add(('user', upn))
                db.add_finding(
                    finding_type='user',
                    value=upn,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=_get_line(output, m.start()),
                    notes='kerbrute valid username',
                )

        # kerbrute — valid password
        for m in _RE_KERBRUTE_PASS.finditer(output):
            upn, pwd = m.group(1), m.group(2).strip()
            if ('cred', upn) not in seen:
                seen.add(('cred', upn))
                db.add_finding(
                    finding_type='credential',
                    value=f'{upn}:{pwd}',
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=m.group(0),
                    notes='kerbrute valid credential',
                )

        # rpcclient / enum4linux users
        for m in _RE_RPCCLIENT_USER.finditer(output):
            username, rid = m.group(1), m.group(2)
            if ('user', username.lower()) not in seen:
                seen.add(('user', username.lower()))
                db.add_finding(
                    finding_type='user',
                    value=username,
                    command_id=cmd_id,
                    confidence=1.0,
                    raw_line=m.group(0),
                    notes=f'rpcclient/enum4linux  RID:{rid}',
                )

    # -----------------------------------------------------------------------
    # Priority 2 — tool-specific parsers
    # -----------------------------------------------------------------------

    def _parse_nmap(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        current_ip: Optional[str] = None
        current_host: Optional[str] = None

        for line in output.splitlines():
            # Host header — reset current target
            mh = _RE_NMAP_HOST.match(line)
            if mh:
                hostname, ip = mh.group(1), mh.group(2)
                if _valid_ip(ip):
                    current_ip = ip
                    current_host = hostname
                    if ('target', ip) not in seen:
                        seen.add(('target', ip))
                        db.upsert_target(ip=ip, hostname=hostname)
                continue

            # Port/service line
            if current_ip:
                mp = _RE_NMAP_PORT.match(line)
                if mp:
                    port_num = int(mp.group(1))
                    proto    = mp.group(2)
                    state    = mp.group(3)
                    service  = mp.group(4)
                    version  = (mp.group(5) or '').strip() or None
                    if 1 <= port_num <= 65535:
                        key = ('port', current_ip, port_num, proto)
                        if key not in seen:
                            seen.add(key)
                            tid = db.upsert_target(ip=current_ip, hostname=current_host)
                            db.upsert_port(
                                target_id=tid,
                                port=port_num,
                                protocol=proto,
                                state=state,
                                service=service,
                                version=version,
                            )

    def _parse_masscan(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_MASSCAN.finditer(output):
            port_num, proto, ip = int(m.group(1)), m.group(2), m.group(3)
            if not _valid_ip(ip) or not (1 <= port_num <= 65535):
                continue
            if ('target', ip) not in seen:
                seen.add(('target', ip))
                db.upsert_target(ip=ip)
            key = ('port', ip, port_num, proto)
            if key not in seen:
                seen.add(key)
                tid = db.upsert_target(ip=ip)
                db.upsert_port(target_id=tid, port=port_num, protocol=proto, state='open')

    def _parse_rustscan(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_RUSTSCAN.finditer(output):
            ip, port_num = m.group(1), int(m.group(2))
            if not _valid_ip(ip) or not (1 <= port_num <= 65535):
                continue
            if ('target', ip) not in seen:
                seen.add(('target', ip))
                db.upsert_target(ip=ip)
            key = ('port', ip, port_num, 'tcp')
            if key not in seen:
                seen.add(key)
                tid = db.upsert_target(ip=ip)
                db.upsert_port(target_id=tid, port=port_num, protocol='tcp', state='open')

    def _parse_nxc(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        # Host info lines [*]
        for m in _RE_NXC_HOST.finditer(output):
            proto, ip, port_num, hostname, info = (
                m.group(1), m.group(2), int(m.group(3)),
                m.group(4), m.group(5),
            )
            if not _valid_ip(ip):
                continue
            # Extract OS from info string e.g. "Windows Server 2016 Standard 14393"
            os_guess = info.split('(')[0].strip() if info else None
            if ('target', ip) not in seen:
                seen.add(('target', ip))
                db.upsert_target(ip=ip, hostname=hostname, os_guess=os_guess)
            key = ('port', ip, port_num, proto.lower())
            if key not in seen and 1 <= port_num <= 65535:
                seen.add(key)
                tid = db.upsert_target(ip=ip)
                db.upsert_port(
                    target_id=tid,
                    port=port_num,
                    protocol='tcp',
                    state='open',
                    service=proto.lower(),
                )

        # Auth success lines [+]
        for m in _RE_NXC_AUTH.finditer(output):
            _, ip, domain, user, pwd = (
                m.group(1), m.group(2), m.group(3), m.group(4), m.group(5),
            )
            if not _valid_ip(ip):
                continue
            upn = f'{domain}\\{user}'
            pwn3d = bool(_RE_NXC_PWND.search(m.group(0)))
            notes = f'nxc auth success  {domain}\\{user}'
            if pwn3d:
                notes += '  (Pwn3d! — local admin)'
            if ('cred', ip, upn) not in seen:
                seen.add(('cred', ip, upn))
                db.add_finding(
                    finding_type='credential',
                    value=f'{upn}:{pwd}' + (' (Pwn3d!)' if pwn3d else ''),
                    command_id=cmd_id,
                    target=ip,
                    confidence=0.95,
                    raw_line=m.group(0),
                    notes=notes,
                )

        # SAM/NTDS hash dump lines
        for m in _RE_NXC_SAM.finditer(output):
            username, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
            val = f'{username}:{rid}:{lm}:{nt}:::'
            if ('hash', username.lower(), nt) not in seen:
                seen.add(('hash', username.lower(), nt))
                db.add_finding(
                    finding_type='hash',
                    value=val,
                    command_id=cmd_id,
                    confidence=0.95,
                    raw_line=m.group(0),
                    notes=f'nxc SAM/NTDS  user:{username}  NT:{nt}',
                )

    def _parse_nuclei(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_NUCLEI.finditer(output):
            template_id, proto, severity, target, extracted = (
                m.group(1), m.group(2), m.group(3),
                m.group(4), m.group(5),
            )
            key = ('nuclei', template_id, target)
            if key not in seen:
                seen.add(key)
                notes = f'nuclei  severity:{severity}  proto:{proto}'
                if extracted:
                    notes += f'  extracted:{extracted}'
                db.add_finding(
                    finding_type='cve' if template_id.upper().startswith('CVE-') else 'service',
                    value=f'[{template_id}] {target}',
                    command_id=cmd_id,
                    confidence=0.95,
                    raw_line=m.group(0),
                    notes=notes,
                )

    def _parse_feroxbuster(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_FEROX.finditer(output):
            status, url = int(m.group(1)), m.group(2)
            if status not in _WEB_INTERESTING:
                continue
            if ('path', url) not in seen:
                seen.add(('path', url))
                db.add_finding(
                    finding_type='path',
                    value=url,
                    command_id=cmd_id,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'feroxbuster  HTTP {status}',
                )

    def _parse_gobuster(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_GOBUSTER.finditer(output):
            path, status = m.group(1), int(m.group(2))
            if status not in _WEB_INTERESTING:
                continue
            if ('path', path) not in seen:
                seen.add(('path', path))
                db.add_finding(
                    finding_type='path',
                    value=path,
                    command_id=cmd_id,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'gobuster  HTTP {status}',
                )

    def _parse_ffuf(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_FFUF.finditer(output):
            fuzz_val, status = m.group(1), int(m.group(2))
            if status not in _WEB_INTERESTING:
                continue
            if ('path', fuzz_val) not in seen:
                seen.add(('path', fuzz_val))
                db.add_finding(
                    finding_type='path',
                    value=fuzz_val,
                    command_id=cmd_id,
                    confidence=0.85,
                    raw_line=m.group(0),
                    notes=f'ffuf  HTTP {status}',
                )

    def _parse_nikto(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_NIKTO_SERVER.finditer(output):
            banner = m.group(1).strip()
            if ('service', banner) not in seen:
                seen.add(('service', banner))
                db.add_finding(
                    finding_type='service',
                    value=banner,
                    command_id=cmd_id,
                    confidence=0.95,
                    raw_line=m.group(0),
                    notes='nikto server banner',
                )
        for m in _RE_NIKTO_OSVDB.finditer(output):
            osvdb_id, path, desc = m.group(1), (m.group(2) or '').strip(), m.group(3).strip()
            val = f'OSVDB-{osvdb_id}: {path}: {desc}' if path else f'OSVDB-{osvdb_id}: {desc}'
            if ('nikto', osvdb_id) not in seen:
                seen.add(('nikto', osvdb_id))
                db.add_finding(
                    finding_type='path',
                    value=val,
                    command_id=cmd_id,
                    confidence=0.85,
                    raw_line=m.group(0),
                    notes=f'nikto OSVDB-{osvdb_id}',
                )

    def _parse_arpscan(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_ARPSCAN.finditer(output):
            ip, mac, vendor = m.group(1), m.group(2), m.group(3).strip()
            if not _valid_ip(ip):
                continue
            if ('target', ip) not in seen:
                seen.add(('target', ip))
                db.upsert_target(ip=ip, notes=f'MAC:{mac}  vendor:{vendor}')

    def _parse_john(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        for m in _RE_JOHN_CRACKED.finditer(output):
            plaintext = m.group(1).strip()
            user_hint = m.group(2).strip()
            if any(plaintext.startswith(p) for p in _JOHN_SKIP_PREFIXES):
                continue
            key = ('cred_cracked', user_hint, plaintext)
            if key not in seen:
                seen.add(key)
                db.add_finding(
                    finding_type='credential',
                    value=f'{user_hint}:{plaintext}',
                    command_id=cmd_id,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'john cracked  user:{user_hint}  plain:{plaintext}',
                )

    def _parse_hashcat(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        # Only parse when a crack actually completed or --show was used
        if 'Cracked' not in output and '--show' not in cmd:
            return
        for m in _RE_HASHCAT_CRACKED.finditer(output):
            hash_val = m.group(1)
            plaintext = m.group(2).strip()
            if not plaintext or len(plaintext) > 128:
                continue
            key = ('hash_cracked', hash_val[:20], plaintext)
            if key not in seen:
                seen.add(key)
                db.add_finding(
                    finding_type='credential',
                    value=f'{hash_val}:{plaintext}',
                    command_id=cmd_id,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'hashcat cracked  plain:{plaintext}',
                )

    def _parse_enum4linux(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        # Users already handled by Priority-1 _RE_RPCCLIENT_USER
        # Shares
        for m in _RE_ENUM4LINUX_SHARE.finditer(output):
            share      = m.group(1)
            share_type = m.group(2)
            comment    = m.group(3).strip()
            key = ('share', share)
            if key not in seen:
                seen.add(key)
                db.add_finding(
                    finding_type='service',
                    value=f'\\\\<host>\\{share}',
                    command_id=cmd_id,
                    confidence=0.85,
                    raw_line=m.group(0),
                    notes=f'enum4linux share  type:{share_type}'
                          + (f'  comment:{comment}' if comment else ''),
                )

    def _parse_smbmap(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        current_ip: Optional[str] = None
        mh = _RE_SMBMAP_HOST.search(output)
        if mh and _valid_ip(mh.group(1)):
            current_ip = mh.group(1)

        for m in _RE_SMBMAP_SHARE.finditer(output):
            share = m.group(1).strip()
            perms = m.group(2).replace(' ', '').upper()   # READONLY / READ,WRITE / etc
            comment = m.group(3).strip()
            key = ('share', share, current_ip)
            if key not in seen:
                seen.add(key)
                val = f'\\\\{current_ip}\\{share}' if current_ip else f'\\\\<host>\\{share}'
                db.add_finding(
                    finding_type='service',
                    value=val,
                    command_id=cmd_id,
                    target=current_ip,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'smbmap  {perms}' + (f'  comment:{comment}' if comment else ''),
                )

    def _parse_sqlmap(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        dbms_m = _RE_SQLMAP_DBMS.search(output)
        dbms   = dbms_m.group(1).strip() if dbms_m else 'unknown'

        for m in _RE_SQLMAP_VULN.finditer(output):
            param = m.group(1)
            key   = ('sqli', param)
            if key not in seen:
                seen.add(key)
                db.add_finding(
                    finding_type='service',
                    value=f'SQLi: param={param} dbms={dbms}',
                    command_id=cmd_id,
                    confidence=0.95,
                    raw_line=_get_line(output, m.start()),
                    notes=f'sqlmap SQL injection  param:{param}  dbms:{dbms}',
                )

    def _parse_evilwinrm(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        m = _RE_EVILWINRM.search(output)
        if not m:
            return
        cwd = m.group(1)
        if ('evilwinrm', cwd) in seen:
            return
        seen.add(('evilwinrm', cwd))

        user_m = re.search(r'-u\s+(\S+)', cmd, re.IGNORECASE)
        ip_m   = re.search(r'-i\s+([\d.]+)', cmd, re.IGNORECASE)
        user   = user_m.group(1) if user_m else 'unknown'
        ip     = ip_m.group(1) if ip_m else None

        db.add_finding(
            finding_type='credential',
            value=f'{user}@{ip or "?"}  [WinRM shell]',
            command_id=cmd_id,
            target=ip,
            service='winrm',
            confidence=0.95,
            raw_line=m.group(0),
            notes=f'evil-winrm shell  user:{user}  cwd:{cwd}',
        )

    def _parse_wpscan(self, db, cmd_id: int, cmd: str, output: str, seen: set) -> None:
        # Insecure WordPress version
        vm = _RE_WPSCAN_WP_VER.search(output)
        if vm:
            ver = vm.group(1)
            if ('wp_version', ver) not in seen:
                seen.add(('wp_version', ver))
                db.add_finding(
                    finding_type='service',
                    value=f'WordPress {ver} (Insecure)',
                    command_id=cmd_id,
                    confidence=0.95,
                    raw_line=vm.group(0),
                    notes='wpscan outdated WordPress version',
                )

        # Users within "User(s) Identified:" section
        sec = _RE_WPSCAN_USERS_HDR.search(output)
        if sec:
            for um in _RE_WPSCAN_USER_LINE.finditer(sec.group(1)):
                username = um.group(1)
                if ('user', username) not in seen:
                    seen.add(('user', username))
                    db.add_finding(
                        finding_type='user',
                        value=username,
                        command_id=cmd_id,
                        confidence=0.9,
                        raw_line=um.group(0),
                        notes='wpscan WordPress user enumeration',
                    )

        # Plugin / theme vulnerability titles
        for m in _RE_WPSCAN_PLUGIN_VULN.finditer(output):
            title = m.group(1).strip()
            if ('wp_vuln', title) not in seen:
                seen.add(('wp_vuln', title))
                cve_m = _RE_CVE.search(title)
                db.add_finding(
                    finding_type='cve' if cve_m else 'service',
                    value=cve_m.group(0) if cve_m else f'WP vuln: {title[:120]}',
                    command_id=cmd_id,
                    confidence=0.9,
                    raw_line=m.group(0),
                    notes=f'wpscan plugin vuln: {title[:120]}',
                )
