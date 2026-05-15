# Nmap - Notes

## Basic Commands
* `nmap <target>` - Scan the 1000 most common ports.
* `nmap -p 22,80,443 <target>` - Scan specific ports.
* `nmap -p 1-1000 <target>` - Scan a range of ports.
* `nmap -F <target>` - Fast scan mode (100 most common ports).

## Scan Types
* `nmap -sS <target>` - TCP SYN Scan (stealthy, fast, half-open).
* `nmap -sT <target>` - TCP Connect Scan (full TCP connection).
* `nmap -sU <target>` - UDP Scan.
* `nmap -sV <target>` - Service version detection.
* `nmap -O <target>` - OS detection.
* `nmap -A <target>` - Aggressive scan (OS, versions, scripts, traceroute).

## NSE Scripts (Nmap Scripting Engine)
* `nmap --script vuln <target>` - Scan for known vulnerabilities.
* `nmap --script http-enum <target>` - HTTP directory enumeration.

## Saving Results
* `nmap -oN output.txt <target>` - Save output to a text file.
* `nmap -oX output.xml <target>` - Save output to XML format.

## Tips
> **Warning:** Only scan devices you have explicit permission to audit.