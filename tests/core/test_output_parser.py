"""Tests for the terminal output parser (core/db/output_parser.py).

The parser turns raw tool output into Findings / Targets / Ports by calling back
into a DB object. We pass a lightweight FakeDB that just records the calls, so
these tests assert the *parsing* behaviour without any real database: the pure
helpers, the Priority-1 global patterns (CVE, hashes, flags, creds), and the
tool-specific parsers (nmap/masscan/rustscan) including target/port upserts.
"""

from core.db import output_parser as op
from core.db.output_parser import OutputParser, _strip_ansi, _valid_ip, _get_line


class FakeDB:
    """Records parser callbacks instead of touching a real database."""

    def __init__(self):
        self.findings = []
        self.targets = []
        self.ports = []
        self._ids = {}

    def add_finding(self, **kw):
        self.findings.append(kw)

    def upsert_target(self, ip, hostname=None, os_guess=None, **extra):
        if ip not in self._ids:
            self._ids[ip] = len(self._ids) + 1
            row = {"ip": ip, "hostname": hostname, "os_guess": os_guess}
            row.update(extra)          # e.g. arp-scan passes notes=
            self.targets.append(row)
        return self._ids[ip]

    def upsert_port(self, **kw):
        self.ports.append(kw)

    def kinds(self):
        return [f["finding_type"] for f in self.findings]


def run(cmd, output, tags=None):
    db = FakeDB()
    OutputParser().process(db=db, cmd_id=1, cmd=cmd, output=output, tags=tags or [])
    return db


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #
def test_strip_ansi_removes_color_codes():
    assert _strip_ansi("\x1b[31mred\x1b[0m text") == "red text"


def test_strip_ansi_leaves_plain_text():
    assert _strip_ansi("nothing to strip") == "nothing to strip"


def test_valid_ip_accepts_dotted_quad():
    assert _valid_ip("10.10.10.5") is True
    assert _valid_ip("255.255.255.255") is True


def test_valid_ip_rejects_bad_input():
    assert _valid_ip("256.1.1.1") is False
    assert _valid_ip("10.10.10") is False
    assert _valid_ip("1.2.3.4.5") is False
    assert _valid_ip("a.b.c.d") is False


def test_get_line_returns_full_containing_line():
    text = "first line\nsecond line\nthird line"
    pos = text.index("second")
    assert _get_line(text, pos) == "second line"


# --------------------------------------------------------------------------- #
# process() guards
# --------------------------------------------------------------------------- #
def test_empty_output_produces_no_calls():
    db = run("nmap 10.10.10.5", "")
    assert db.findings == [] and db.targets == [] and db.ports == []


def test_whitespace_only_output_produces_no_calls():
    db = run("nmap 10.10.10.5", "   \n\t\n")
    assert db.findings == [] and db.targets == []


def test_unknown_tool_still_runs_priority1_without_error():
    db = run("some-weird-tool", "found CVE-2021-4034 in the wild\n")
    assert ("cve", "CVE-2021-4034") in {(f["finding_type"], f["value"]) for f in db.findings}


# --------------------------------------------------------------------------- #
# Priority-1 global patterns
# --------------------------------------------------------------------------- #
def test_cve_is_extracted():
    db = run("echo", "Vulnerable to CVE-2017-0144 and CVE-2021-4034.\n")
    values = {f["value"] for f in db.findings if f["finding_type"] == "cve"}
    assert values == {"CVE-2017-0144", "CVE-2021-4034"}


def test_duplicate_cve_recorded_once():
    db = run("echo", "CVE-2021-4034 ... later again CVE-2021-4034\n")
    cves = [f for f in db.findings if f["finding_type"] == "cve"]
    assert len(cves) == 1


def test_ctf_flag_is_extracted():
    db = run("cat", "the flag is HTB{c4tch_m3_1f_y0u_c4n} nice\n")
    flags = [f for f in db.findings if f["finding_type"] == "flag"]
    assert len(flags) == 1
    assert flags[0]["value"] == "HTB{c4tch_m3_1f_y0u_c4n}"


def test_ntlm_hash_line_is_extracted():
    line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    db = run("secretsdump.py", line + "\n")
    hashes = [f for f in db.findings if f["finding_type"] == "hash"]
    assert len(hashes) == 1
    assert "NT:31d6cfe0d16ae931b73c59d7e0c089c0" in hashes[0]["notes"]


def test_hydra_credential_is_extracted_with_target():
    out = "[22][ssh] host: 10.10.10.5   login: root   password: toor\n"
    db = run("hydra", out)
    creds = [f for f in db.findings if f["finding_type"] == "credential"]
    assert len(creds) == 1
    assert creds[0]["value"] == "root:toor"
    assert creds[0]["target"] == "10.10.10.5"
    assert creds[0]["port"] == 22


def test_credential_with_invalid_ip_is_skipped():
    out = "[22][ssh] host: 999.999.999.999   login: root   password: toor\n"
    db = run("hydra", out)
    assert [f for f in db.findings if f["finding_type"] == "credential"] == []


def test_priority1_runs_on_ansi_colored_output():
    out = "\x1b[32m[+]\x1b[0m found CVE-2021-4034\n"
    db = run("echo", out)
    assert any(f["finding_type"] == "cve" for f in db.findings)


# --------------------------------------------------------------------------- #
# tool-specific parsers — targets & ports
# --------------------------------------------------------------------------- #
def test_nmap_extracts_target_and_ports():
    out = (
        "Nmap scan report for target.htb (10.10.10.5)\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 8.2\n"
        "80/tcp   open  http    nginx 1.18\n"
    )
    db = run("nmap -sV 10.10.10.5", out)
    assert db.targets == [{"ip": "10.10.10.5", "hostname": "target.htb", "os_guess": None}]
    ports = {(p["port"], p["protocol"], p["service"]) for p in db.ports}
    assert (22, "tcp", "ssh") in ports
    assert (80, "tcp", "http") in ports


def test_nmap_records_service_version():
    out = (
        "Nmap scan report for 10.10.10.5\n"
        "22/tcp   open  ssh     OpenSSH 8.2\n"
    )
    db = run("nmap", out)
    ssh = [p for p in db.ports if p["port"] == 22][0]
    assert ssh["version"] == "OpenSSH 8.2"
    assert ssh["state"] == "open"


def test_masscan_extracts_open_port():
    out = "Discovered open port 443/tcp on 10.10.10.9\n"
    db = run("masscan", out)
    assert db.targets == [{"ip": "10.10.10.9", "hostname": None, "os_guess": None}]
    assert db.ports[0]["port"] == 443
    assert db.ports[0]["state"] == "open"


def test_rustscan_extracts_open_port():
    out = "Open 10.10.10.7:8080\n"
    db = run("rustscan -a 10.10.10.7", out)
    assert db.targets == [{"ip": "10.10.10.7", "hostname": None, "os_guess": None}]
    assert db.ports[0]["port"] == 8080
    assert db.ports[0]["protocol"] == "tcp"


def test_scanner_ignores_out_of_range_or_bad_ip():
    out = "Discovered open port 22/tcp on 300.1.1.1\n"
    db = run("masscan", out)
    assert db.targets == [] and db.ports == []


# --------------------------------------------------------------------------- #
# web content discovery — feroxbuster / gobuster / ffuf
# --------------------------------------------------------------------------- #
def test_feroxbuster_records_interesting_path():
    out = "200      GET       12l       34w      500c http://target/admin\n"
    db = run("feroxbuster", out)
    paths = [f for f in db.findings if f["finding_type"] == "path"]
    assert len(paths) == 1
    assert paths[0]["value"] == "http://target/admin"


def test_feroxbuster_skips_uninteresting_status():
    out = "404      GET       12l       34w      500c http://target/nope\n"
    db = run("feroxbuster", out)
    assert [f for f in db.findings if f["finding_type"] == "path"] == []


def test_gobuster_records_path_with_status():
    out = "/admin               (Status: 301) [Size: 312]\n"
    db = run("gobuster dir -u http://target", out)
    paths = [f for f in db.findings if f["finding_type"] == "path"]
    assert len(paths) == 1
    assert paths[0]["value"] == "/admin"


def test_ffuf_records_fuzz_hit():
    out = "admin                   [Status: 200, Size: 1234, Words: 56, Lines: 7]\n"
    db = run("ffuf -w list.txt -u http://target/FUZZ", out)
    paths = [f for f in db.findings if f["finding_type"] == "path"]
    assert len(paths) == 1
    assert paths[0]["value"] == "admin"


def test_duplicate_path_recorded_once():
    out = (
        "/admin               (Status: 301) [Size: 312]\n"
        "/admin               (Status: 301) [Size: 312]\n"
    )
    db = run("gobuster", out)
    assert len([f for f in db.findings if f["finding_type"] == "path"]) == 1


# --------------------------------------------------------------------------- #
# nikto server banner
# --------------------------------------------------------------------------- #
def test_nikto_records_server_banner():
    out = "+ Server: Apache/2.4.49 (Unix)\n"
    db = run("nikto -h target", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert len(svc) == 1
    assert svc[0]["value"] == "Apache/2.4.49 (Unix)"


# --------------------------------------------------------------------------- #
# cracked credentials — john / hashcat
# --------------------------------------------------------------------------- #
def test_john_records_cracked_credential():
    out = "Password123      (admin)\n"
    db = run("john --show hashes.txt", out)
    creds = [f for f in db.findings if f["finding_type"] == "credential"]
    assert len(creds) == 1
    assert creds[0]["value"] == "admin:Password123"


def test_john_skips_status_lines():
    out = "Warning: only      (foo)\n"
    db = run("john", out)
    assert [f for f in db.findings if f["finding_type"] == "credential"] == []


def test_hashcat_records_cracked_when_cracked_present():
    out = "Status...........: Cracked\n5f4dcc3b5aa765d61d8327deb882cf99:password\n"
    db = run("hashcat -m 0 hash.txt list.txt", out)
    creds = [f for f in db.findings if f["finding_type"] == "credential"]
    assert len(creds) == 1
    assert creds[0]["value"] == "5f4dcc3b5aa765d61d8327deb882cf99:password"


def test_hashcat_noop_without_cracked_or_show():
    out = "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
    db = run("hashcat -m 0 hash.txt list.txt", out)
    assert [f for f in db.findings if f["finding_type"] == "credential"] == []


# --------------------------------------------------------------------------- #
# netexec / nxc — hosts, auth, Pwn3d
# --------------------------------------------------------------------------- #
def test_nxc_host_line_records_target_and_port():
    out = ("SMB   10.10.10.5   445   DC01   [*] Windows Server 2016 Standard "
           "14393 (name:DC01) (domain:corp.local)\n")
    db = run("nxc smb 10.10.10.5", out)
    assert db.targets[0]["ip"] == "10.10.10.5"
    assert db.targets[0]["hostname"] == "DC01"
    assert db.targets[0]["os_guess"].startswith("Windows Server 2016")
    assert any(p["port"] == 445 for p in db.ports)


def test_nxc_auth_success_records_credential():
    out = ("SMB   10.10.10.5   445   DC01   [+] "
           "corp.local\\administrator:Password123 (Pwn3d!)\n")
    db = run("nxc smb 10.10.10.5 -u administrator -p Password123", out)
    creds = [f for f in db.findings if f["finding_type"] == "credential"]
    assert len(creds) == 1
    assert "administrator" in creds[0]["value"]
    assert "Password123" in creds[0]["value"]
    assert creds[0]["target"] == "10.10.10.5"
    # NOTE (documents current behaviour): the "(Pwn3d!)" marker is NOT reflected
    # here — _RE_NXC_AUTH stops matching at the password, so the trailing
    # " (Pwn3d!)" falls outside m.group(0) that the Pwn3d check scans. The
    # local-admin flag is therefore silently dropped for this line format.
    assert "Pwn3d" not in creds[0]["value"]


# --------------------------------------------------------------------------- #
# enum4linux / smbmap — shares
# --------------------------------------------------------------------------- #
def test_enum4linux_records_share():
    out = "\n  ADMIN$        Disk      Remote Admin\n"
    db = run("enum4linux -a 10.10.10.5", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert len(svc) == 1
    assert "ADMIN$" in svc[0]["value"]


def test_smbmap_records_share_with_host():
    out = ("[+] IP: 10.10.10.5:445\tName: target.htb\n"
           "\tADMIN$           READ ONLY\tRemote Admin\n")
    db = run("smbmap -H 10.10.10.5", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert len(svc) == 1
    assert "10.10.10.5" in svc[0]["value"]
    assert "ADMIN$" in svc[0]["value"]


# --------------------------------------------------------------------------- #
# sqlmap / evil-winrm
# --------------------------------------------------------------------------- #
def test_sqlmap_records_injectable_param_with_dbms():
    out = "back-end DBMS is MySQL\nParameter 'id' is vulnerable.\n"
    db = run("sqlmap -u http://target/?id=1", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert len(svc) == 1
    assert "param=id" in svc[0]["value"]
    assert "MySQL" in svc[0]["value"]


def test_evilwinrm_records_shell_credential():
    out = "*Evil-WinRM* PS C:\\Users\\admin\\Documents> \n"
    db = run("evil-winrm -i 10.10.10.5 -u admin -p pass", out)
    creds = [f for f in db.findings if f["finding_type"] == "credential"]
    assert len(creds) == 1
    assert creds[0]["service"] == "winrm"
    assert creds[0]["target"] == "10.10.10.5"
    assert "admin" in creds[0]["value"]


# --------------------------------------------------------------------------- #
# wpscan — version, plugin vuln (with/without CVE)
# --------------------------------------------------------------------------- #
def test_wpscan_records_insecure_version():
    out = "[+] WordPress version 5.7.1 identified (Insecure, released 2021-04-06).\n"
    db = run("wpscan --url http://target", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert any("WordPress 5.7.1" in f["value"] for f in svc)


def test_wpscan_plugin_vuln_without_cve_is_service():
    out = "[!] Title: Contact Form 7 <= 5.3.1 - Unrestricted File Upload\n"
    db = run("wpscan --url http://target", out)
    svc = [f for f in db.findings if f["finding_type"] == "service"]
    assert any("WP vuln" in f["value"] for f in svc)


def test_wpscan_plugin_vuln_with_cve_is_cve():
    out = "[!] Title: Some Plugin - RCE (CVE-2021-24145)\n"
    db = run("wpscan --url http://target", out)
    cves = [f for f in db.findings if f["finding_type"] == "cve"]
    assert any(f["value"] == "CVE-2021-24145" for f in cves)


# --------------------------------------------------------------------------- #
# arp-scan — local target discovery
# --------------------------------------------------------------------------- #
def test_arpscan_records_target():
    out = "10.10.10.5\t00:11:22:33:44:55\tVendor Inc\n"
    db = run("arp-scan -l", out)
    assert db.targets[0]["ip"] == "10.10.10.5"
