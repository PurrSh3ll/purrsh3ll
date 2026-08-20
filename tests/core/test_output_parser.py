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

    def upsert_target(self, ip, hostname=None, os_guess=None):
        if ip not in self._ids:
            self._ids[ip] = len(self._ids) + 1
            self.targets.append({"ip": ip, "hostname": hostname, "os_guess": os_guess})
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
