"""Tests for pshunter's nmap <host> element parsers (nmap_parse).

Each parser takes one nmap <host> ElementTree element and returns the plain dict
a phase stores (up-hosts / open ports / service detail). We build the elements
from XML strings — pure, no scanning.
"""

import xml.etree.ElementTree as ET

from nmap_parse import _host_from_elem, _host_ports_from_elem, _host_detail_from_elem


def _host(xml):
    return ET.fromstring(xml)


# --------------------------------------------------------------------------- #
# _host_from_elem  (-sn discovery)
# --------------------------------------------------------------------------- #
def test_up_host_full():
    elem = _host("""
      <host>
        <status state="up"/>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="VendorInc"/>
        <hostnames><hostname name="target.htb"/></hostnames>
      </host>""")
    assert _host_from_elem(elem) == {
        "ip": "10.10.10.5", "mac": "00:11:22:33:44:55",
        "vendor": "VendorInc", "hostname": "target.htb"}


def test_down_host_is_none():
    elem = _host('<host><status state="down"/>'
                 '<address addr="10.10.10.5" addrtype="ipv4"/></host>')
    assert _host_from_elem(elem) is None


def test_host_without_ipv4_is_none():
    elem = _host('<host><status state="up"/>'
                 '<address addr="00:11:22:33:44:55" addrtype="mac"/></host>')
    assert _host_from_elem(elem) is None


def test_host_without_hostname():
    elem = _host('<host><status state="up"/>'
                 '<address addr="10.10.10.5" addrtype="ipv4"/></host>')
    assert _host_from_elem(elem)["hostname"] is None


# --------------------------------------------------------------------------- #
# _host_ports_from_elem
# --------------------------------------------------------------------------- #
def test_open_ports_extracted_closed_skipped():
    elem = _host("""
      <host>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <ports>
          <port portid="22" protocol="tcp"><state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.2"/></port>
          <port portid="81" protocol="tcp"><state state="closed"/></port>
          <port portid="443" protocol="tcp"><state state="open|filtered"/></port>
        </ports>
      </host>""")
    res = _host_ports_from_elem(elem)
    ports = {p["port"]: p for p in res["ports"]}
    assert set(ports) == {22, 443}                 # 81 closed → skipped
    assert ports[22]["service"]["name"] == "ssh"
    assert ports[443]["state"] == "open|filtered"
    assert ports[443]["service"] is None


def test_no_open_ports_returns_none():
    elem = _host('<host><address addr="10.10.10.5" addrtype="ipv4"/>'
                 '<ports><port portid="81" protocol="tcp"><state state="closed"/>'
                 '</port></ports></host>')
    assert _host_ports_from_elem(elem) is None


def test_ports_without_ipv4_is_none():
    elem = _host('<host><ports><port portid="22" protocol="tcp">'
                 '<state state="open"/></port></ports></host>')
    assert _host_ports_from_elem(elem) is None


# --------------------------------------------------------------------------- #
# _host_detail_from_elem  (-sV -sC -O)
# --------------------------------------------------------------------------- #
def test_service_detail_prefers_application_cpe():
    elem = _host("""
      <host>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <ports>
          <port portid="22" protocol="tcp">
            <service name="ssh" product="OpenSSH" version="8.2"
                     method="probed" hostname="cn.target.htb">
              <cpe>cpe:/o:linux:linux_kernel</cpe>
              <cpe>cpe:/a:openbsd:openssh:8.2</cpe>
            </service>
            <script id="ssh-hostkey" output="key data"/>
          </port>
        </ports>
        <hostscript><script id="smb-os-discovery" output="host script out"/></hostscript>
        <os><osmatch name="Linux 5.X"/></os>
      </host>""")
    d = _host_detail_from_elem(elem)
    assert d["os"] == "Linux 5.X"
    assert d["services"][0]["cpe"] == "cpe:/a:openbsd:openssh:8.2"   # /a preferred over /o
    assert d["services"][0]["version"] == "8.2"
    # one port-level script + one host-level (port 0)
    ports_with_scripts = sorted(s["port"] for s in d["scripts"])
    assert ports_with_scripts == [0, 22]
    assert d["hostnames"][0]["hostname"] == "cn.target.htb"


def test_non_probed_service_not_in_services():
    elem = _host("""
      <host>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <ports>
          <port portid="22" protocol="tcp">
            <service name="ssh" method="table"/>
          </port>
        </ports>
      </host>""")
    # No probed service, no scripts, no OS → nothing to report.
    assert _host_detail_from_elem(elem) is None


def test_detail_without_ipv4_is_none():
    elem = _host('<host><os><osmatch name="Linux"/></os></host>')
    assert _host_detail_from_elem(elem) is None
