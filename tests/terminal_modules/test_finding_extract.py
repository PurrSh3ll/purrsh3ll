"""Tests for pshunter's finding extractor (finding_extract._extract_finding).

The extractor is a large, pure rule engine: given an NSE/tool script id and its
raw output text it returns a finding dict or None. These tests pin the main
representative branches (standard vuln format, auth scripts, a few info folders,
credential findings) plus the shared CVE parsing and None short-circuits — not
every single rule, to stay robust against wording tweaks.
"""

from finding_extract import _extract_finding as extract


# --------------------------------------------------------------------------- #
# shared behaviour
# --------------------------------------------------------------------------- #
def test_empty_output_returns_none():
    assert extract("anything", "") is None
    assert extract("anything", None) is None


def test_unknown_script_with_no_signal_returns_none():
    assert extract("some-random-script", "just some boring text\n") is None


# --------------------------------------------------------------------------- #
# 1) standard vuln library format
# --------------------------------------------------------------------------- #
def test_vulnerable_state_with_risk_and_human_summary():
    output = (
        "VULNERABLE:\n"
        "Remote Code Execution in SMBv1\n"
        "  State: VULNERABLE\n"
        "  Risk factor: High\n"
        "  IDs: CVE-2017-0144\n"
    )
    f = extract("smb-vuln-ms17-010", output)
    assert f["state"] == "VULNERABLE"
    assert f["risk"] == "HIGH"
    assert f["summary"] == "Remote Code Execution in SMBv1"
    assert f["cve"] == "CVE-2017-0144"


def test_likely_vulnerable_state():
    output = "  State: LIKELY VULNERABLE\n  Risk factor: Medium\n"
    f = extract("some-vuln", output)
    assert f["state"] == "LIKELY"
    assert f["risk"] == "MEDIUM"


def test_vuln_defaults_risk_high_when_absent():
    f = extract("some-vuln", "  State: VULNERABLE\n")
    assert f["risk"] == "HIGH"
    # No human name line, so it falls back to the script id.
    assert f["summary"] == "some-vuln"


def test_cves_deduped_and_sorted():
    output = (
        "  State: VULNERABLE\n"
        "  IDs: CVE-2021-4034 CVE-2017-0144 CVE-2021-4034\n"
    )
    f = extract("multi", output)
    assert f["cve"] == "CVE-2017-0144,CVE-2021-4034"


# --------------------------------------------------------------------------- #
# 2) auth-category scripts
# --------------------------------------------------------------------------- #
def test_auth_script_any_output_is_weakness():
    f = extract("ftp-anon", "Anonymous FTP login allowed (FTP code 230)\n")
    assert f["state"] == "EXPOSED"
    assert f["risk"] == "HIGH"
    assert f["summary"] == "anonymous FTP login allowed"


# --------------------------------------------------------------------------- #
# representative info / credential folders
# --------------------------------------------------------------------------- #
def test_http_headers_folds_tech_and_missing_headers():
    output = "Server: Apache/2.4.49\nX-Powered-By: PHP/7.4\n"
    f = extract("http-headers", output)
    assert f["state"] == "INFO"
    assert "tech:" in f["summary"]
    assert "Apache/2.4.49" in f["summary"]
    assert "missing sec-headers:" in f["summary"]


def test_searchsploit_folds_edb_candidates():
    output = "[EXPLOIT] Apache 2.4.49 - Path Traversal (EDB-50383)\n"
    f = extract("searchsploit", output)
    assert f["state"] == "INFO"
    assert f["risk"] == "MEDIUM"
    assert "EDB-50383" in f["summary"]


def test_default_creds_is_high_vulnerable():
    output = "  ! admin:admin @ http://t/login (form)\n"
    f = extract("default-creds", output)
    assert f["state"] == "VULNERABLE"
    assert f["risk"] == "HIGH"
    assert "admin:admin" in f["summary"]


def test_summary_is_truncated_to_140_chars():
    long_name = "X" * 300
    output = f"VULNERABLE:\n{long_name}\n  State: VULNERABLE\n"
    f = extract("big", output)
    assert len(f["summary"]) <= 140
