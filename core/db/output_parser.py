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
            if ('cred', ip, upn) not in seen:
                seen.add(('cred', ip, upn))
                db.add_finding(
                    finding_type='credential',
                    value=f'{upn}:{pwd}',
                    command_id=cmd_id,
                    target=ip,
                    confidence=0.95,
                    raw_line=m.group(0),
                    notes=f'nxc auth success  {domain}\\{user}',
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
