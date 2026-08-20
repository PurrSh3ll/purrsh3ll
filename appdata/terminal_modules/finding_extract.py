#!/usr/bin/env python3
# PurrSh3ll — pshunter NSE-output → finding extraction
# Copyright (C) 2024-2025  PurrSh3ll Contributors
#
# Pure, side-effect-free finding extraction lifted out of pshunter so this large,
# rule-dense logic can be unit-tested in isolation. Given one NSE script id plus
# its output text it returns a finding dict (or None) — no I/O, no DB, no scans
# (the output is already stored); its only input is the two strings.

import re


# Auth-category scripts whose mere output is a weakness → a one-line title each.
_AUTH_TITLE = {
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


# Discovered dir-brute paths worth elevating to MEDIUM: admin/login surfaces,
# config/backup/dump artifacts and exposed VCS/secret files. Kept deliberately
# tight (high-signal only) so most plain content stays LOW.
_DIRB_SENSITIVE = re.compile(
    r"(?i)(?:^|/)(?:admin|login|dashboard|console|manager|adminer|phpmyadmin|"
    r"wp-admin|wp-login|config|configuration|settings|backup|backups|dump|"
    r"phpinfo|server-status|actuator|\.git|\.svn|\.hg|\.env|\.htpasswd|"
    r"id_rsa|id_dsa|\.ssh|\.sql|\.bak|\.old|\.swp|credentials?|secrets?)")

# Exposed VCS / backup / secret artifacts that leak source, credentials or data
# outright → HIGH (a strict subset of the sensitive set above).
_VCS_HIGH_RE = re.compile(
    r"(?i)(?:\.git/|\.svn/|\.hg/|\.env\b|\.sql\b|\.bak\b|\.old\b|dump|backup|"
    r"id_rsa|id_dsa|\.pem\b|\.ppk\b|credentials?|passwo?rd|secrets?|"
    r"wp-config|config\.php|\.htpasswd|\.ssh/)")

# GET/POST parameter names that imply an injection / path-traversal / SSRF /
# open-redirect surface → MEDIUM. Generic search-ish names (q, search, name…)
# are intentionally excluded to avoid marking almost everything.
_PARAM_DANGEROUS = {
    "id", "file", "filename", "filepath", "path", "dir", "folder", "page",
    "template", "include", "load", "document", "doc", "read", "download",
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "return", "returnurl", "next", "continue", "callback",
    "cmd", "exec", "command", "query", "data", "img", "image",
}


def _extract_finding(sid: str, output: str) -> "dict | None":
    """Turn one NSE script result into a finding, or None. Covers three sources with
    no re-scan (the output is already in the DB): the standard `vuln` library format
    (State: VULNERABLE / LIKELY), auth scripts whose output implies a weakness, and a
    few info rules over -sC output (exposed .git, weak TLS, SMB signing, …)."""
    if not output:
        return None
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", output)))
    cve = ",".join(cves) or None

    # 1) standard vuln library format
    if re.search(r"State:\s*VULNERABLE", output):
        state = "VULNERABLE"
    elif re.search(r"State:\s*LIKELY VULNERABLE", output):
        state = "LIKELY"
    else:
        state = None
    if state:
        m = re.search(r"Risk factor:\s*([A-Za-z]+)", output)
        risk = (m.group(1).upper() if m else "HIGH")
        # title = the line right after "VULNERABLE:" (the human name), if it isn't a
        # structured field; otherwise fall back to the script id.
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        summary = sid
        for i, ln in enumerate(lines):
            if re.match(r"(LIKELY )?VULNERABLE:?$", ln, re.I) and i + 1 < len(lines):
                nxt = lines[i + 1]
                if not re.match(r"(State|IDs|Risk|Disclosure|References|Description|Extra)\b", nxt):
                    summary = nxt
                break
        return {"state": state, "cve": cve, "risk": risk, "summary": summary[:140]}

    # 2) auth-category scripts: any output = weakness
    if sid in _AUTH_TITLE:
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH", "summary": _AUTH_TITLE[sid]}

    # 2b) http-headers tool: fold the tech banner + missing security headers into one finding
    if sid == "http-headers":
        tech = []
        for hdr in ("Server", "X-Powered-By"):
            m = re.search(rf"^{hdr}:\s*(.+)$", output, re.I | re.M)
            if m:
                tech.append(m.group(1).strip())
        wanted = [("content-security-policy", "CSP"), ("x-frame-options", "X-Frame-Options"),
                  ("x-content-type-options", "X-Content-Type-Options")]
        if re.match(r"\s*https://", output, re.I):          # HSTS only matters over TLS
            wanted.append(("strict-transport-security", "HSTS"))
        missing = [short for hdr, short in wanted
                   if not re.search(rf"^{re.escape(hdr)}:", output, re.I | re.M)]
        parts = []
        if tech:
            parts.append("tech: " + ", ".join(tech))
        if missing:
            parts.append("missing sec-headers: " + ", ".join(missing))
        if parts:
            return {"state": "INFO", "cve": cve, "risk": "LOW" if missing else "INFO",
                    "summary": " · ".join(parts)[:140]}
        return None

    # 2c) whatweb stack fingerprint: fold server / framework / CMS + versions into a finding
    if sid == "http-fingerprint":
        interesting = {
            "apache", "nginx", "microsoft-iis", "litespeed", "openresty", "tomcat", "jetty",
            "php", "asp.net", "x-powered-by", "python", "ruby", "django", "express", "laravel",
            "nodejs", "node.js", "wordpress", "drupal", "joomla", "magento", "mediawiki",
            "typo3", "moodle", "jenkins", "jira", "gitlab", "phpmyadmin",
        }
        tech, seen = [], set()
        for name, val in re.findall(r"([A-Za-z0-9_.-]+)\[([^\]]*)\]", output):
            if name.lower() not in interesting:
                continue
            val = val.strip()
            item = f"{name} {val}" if val else name
            if item.lower() not in seen:
                seen.add(item.lower())
                tech.append(item)
        if tech:
            return {"state": "INFO", "cve": cve, "risk": "INFO",
                    "summary": ("stack: " + ", ".join(tech))[:140]}
        return None

    # 2d) TLS cert (openssl / nmap ssl-cert): surface emails + self-signed note. SAN/CN
    #     hostnames go to the hostnames table via _extract_hostnames, not here.
    if sid == "ssl-cert":
        emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", output)))
        selfsigned = bool(re.search(r"self[- ]signed", output, re.I))
        parts = []
        if emails:
            parts.append("emails: " + ", ".join(emails))
        if selfsigned:
            parts.append("self-signed cert")
        if parts:
            return {"state": "INFO", "cve": cve, "risk": "LOW" if selfsigned else "INFO",
                    "summary": " · ".join(parts)[:140]}
        return None

    # 2e) searchsploit: fold Exploit-DB candidate matches into one finding (leads, not proof)
    if sid == "searchsploit":
        titles = re.findall(r"^\[.*?\]\s*(.+?)\s*\(EDB-(\d+)\)", output, re.M)
        if not titles:
            return None
        items = [f"{t} (EDB-{e})" for t, e in titles]
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM",
                "summary": ("exploits: " + "; ".join(items))[:140]}

    # 2f) http-source: fold mined secrets / endpoints / comments counts into one finding
    if sid == "http-source":
        def _count(sec):
            mm = re.search(rf"{sec} \((\d+)\)", output)
            return int(mm.group(1)) if mm else 0
        nsec, neps, ncom = _count("POTENTIAL SECRETS"), _count("ENDPOINTS"), _count("HTML COMMENTS")
        if not (nsec or neps or ncom):
            return None
        parts = []
        if nsec:
            labels = sorted(set(re.findall(r"^  ([a-z-]+):",
                            output[output.find("POTENTIAL SECRETS"):], re.M)))
            parts.append("secrets: " + (", ".join(labels) if labels else str(nsec)))
        if neps:
            parts.append(f"endpoints: {neps}")
        if ncom:
            parts.append(f"comments: {ncom}")
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if nsec else "INFO",
                "summary": (" · ".join(parts))[:140]}

    # 2g) http-wellknown: fold robots/sitemap hidden paths + error-page tech leak into a finding
    if sid == "http-wellknown":
        def _c(sec):
            mm = re.search(rf"{sec} \((\d+)\)", output)
            return int(mm.group(1)) if mm else 0
        nrob, nsm, nwk = _c("ROBOTS PATHS"), _c("SITEMAP URLS"), _c("WELL-KNOWN")
        techm = re.search(r"^ERROR-PAGE TECH:\s*(.+)$", output, re.M)
        tech = techm.group(1).strip() if techm else ""
        if not (nrob or nsm or nwk or tech):
            return None
        parts = []
        if nrob:
            parts.append(f"robots: {nrob} paths")
        if nsm:
            parts.append(f"sitemap: {nsm} urls")
        if nwk:
            parts.append(f"well-known: {nwk}")
        if tech:
            parts.append("errorpage: " + tech)
        return {"state": "INFO", "cve": cve, "risk": "LOW" if (nrob or tech) else "INFO",
                "summary": (" · ".join(parts))[:140]}

    # 2h) http-cookies: JWT compromise (alg:none / weak secret) or missing cookie flags
    if sid == "http-cookies":
        jwt_hi = re.findall(r"⚠ (alg:none[^\n]*|weak HS256 secret: '[^']+')", output)
        gaps = re.findall(r"^  ([^:]+): missing ([A-Za-z,]+)", output, re.M)
        parts = []
        if jwt_hi:
            parts.append("JWT: " + "; ".join(jwt_hi))
        if gaps:
            parts.append("cookies: " + ", ".join(f"{n} missing {m}" for n, m in gaps[:4]))
        if not parts:
            return None
        sensitive = any(("Secure" in m or "HttpOnly" in m) for _n, m in gaps)
        risk = "HIGH" if jwt_hi else ("MEDIUM" if sensitive else "LOW")
        return {"state": "EXPOSED" if jwt_hi else "INFO", "cve": cve, "risk": risk,
                "summary": (" · ".join(parts))[:140]}

    # 2i) vhost-fuzz: virtual hosts discovered on this IP (each may hold its own app/vuln)
    if sid == "vhost-fuzz":
        vhosts = re.findall(r"^  \+ ([A-Za-z0-9_.-]+)", output, re.M)
        if not vhosts:
            return None
        shown = ", ".join(vhosts[:6]) + (f" +{len(vhosts) - 6} more" if len(vhosts) > 6 else "")
        return {"state": "INFO", "cve": cve, "risk": "LOW",
                "summary": f"vhosts: {shown} ({len(vhosts)})"[:140]}

    # 2j) dir-brute: discovered paths/files; elevate when something sensitive turns up
    if sid == "dir-brute":
        hits = re.findall(r"^\s*\+ (\d{3})\s+(\S+)", output, re.M)
        if not hits:
            return None
        shown = ", ".join(f"{p} ({s})" for s, p in hits[:6]) + \
            (f" +{len(hits) - 6} more" if len(hits) > 6 else "")
        sensitive = any(_DIRB_SENSITIVE.search(p) for _s, p in hits)
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if sensitive else "LOW",
                "summary": f"paths: {shown} ({len(hits)})"[:140]}

    # 2k) vcs-hunt: exposed VCS / backups / secrets — high when source/creds/data can leak
    if sid == "vcs-hunt":
        hits = re.findall(r"^\s*[!+] \d{3}\s+(\S+)", output, re.M)
        if not hits:
            return None
        shown = ", ".join(hits[:6]) + (f" +{len(hits) - 6} more" if len(hits) > 6 else "")
        high = any(_VCS_HIGH_RE.search(p) for p in hits)
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if high else "MEDIUM",
                "summary": f"exposed: {shown} ({len(hits)})"[:140]}

    # 2l) param-hunt: hidden GET params; MEDIUM when a param name implies injection surface
    if sid == "param-hunt":
        groups = re.findall(r"^\s+(\S+?)\?\[([^\]]+)\]", output, re.M)
        if not groups:
            return None
        params = {p.strip() for _e, ps in groups for p in ps.split(",") if p.strip()}
        shown = "; ".join(f"{e}?[{ps}]" for e, ps in groups[:4]) + (" …" if len(groups) > 4 else "")
        danger = params & _PARAM_DANGEROUS
        summ = f"params: {shown} ({len(params)})"
        if danger:
            summ += " · risky: " + ",".join(sorted(danger)[:6])
        return {"state": "INFO", "cve": cve, "risk": "MEDIUM" if danger else "LOW",
                "summary": summ[:140]}

    # 2m) default-creds: working default logins = immediate foothold → high
    if sid == "default-creds":
        hits = re.findall(r"^\s*! (\S+) @ (\S+) \((\w+)\)", output, re.M)
        if not hits:
            return None
        shown = "; ".join(f"{c} @ {p}" for c, p, _t in hits[:4]) + (" …" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"default creds: {shown} ({len(hits)})"[:140]}

    # 2n) auth-bypass: SQLi login bypass (highest) → DB error → user enumeration
    if sid == "auth-bypass":
        byp = re.findall(r"BYPASS (\S+)", output)
        err = re.findall(r"SQLERROR (\S+)", output)
        enum = re.findall(r"ENUM (\S+)", output)
        if byp:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SQLi auth bypass: {', '.join(byp[:3])} ({len(byp)})"[:140]}
        if err:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SQLi login (DB error): {', '.join(err[:3])} ({len(err)})"[:140]}
        if enum:
            return {"state": "INFO", "cve": cve, "risk": "MEDIUM",
                    "summary": f"user enumeration: {', '.join(enum[:3])} ({len(enum)})"[:140]}
        return None

    # 2o) login-brute: cracked creds (foothold) → high; lockout gate tripped → info
    if sid == "login-brute":
        cracked = re.findall(r"CRACKED (\S+) @ (\S+)", output)
        lock = re.findall(r"LOCKOUT (\S+)", output)
        if cracked:
            shown = "; ".join(f"{c} @ {p}" for c, p in cracked[:3]) + (" …" if len(cracked) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"brute-forced: {shown} ({len(cracked)})"[:140]}
        if lock:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"brute skipped — lockout: {', '.join(lock[:3])}"[:140]}
        return None

    # 2p) sqli-scan: injectable params (error/boolean/time) → sqlmap enum/dump
    if sid == "sqli-scan":
        pts = re.findall(r"✗ SQLI (\S+)", output)
        if not pts:
            return None
        dumped = "; dumped" if re.search(r"dumped: yes", output) else ""
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SQLi: {shown} ({len(pts)}){dumped}"[:140]}

    # 2q) sqli-dump: OSCP-safe extraction — real data pulled = confirmed + looted
    if sid == "sqli-dump":
        pts = re.findall(r"✗ (\S+)", output)
        if not pts:
            return None
        db = re.search(r"db: (\S+)", output)
        looted = "; rows dumped" if re.search(r"^\s{8}\S", output, re.M) else ""
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        extra = (f"; db {db.group(1)}" if db else "") + looted
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SQLi dump: {shown} ({len(pts)}){extra}"[:140]}

    # 2r) lfi-scan: local file read confirmed by content signature → high
    if sid == "lfi-scan":
        pts = re.findall(r"✗ LFI (\S+)", output)
        if not pts:
            return None
        caps = []
        if "/etc/passwd via" in output:
            caps.append("/etc/passwd")
        if "php://filter source readable" in output:
            caps.append("source")
        if "/proc/self/environ readable" in output:
            caps.append("environ")
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        tail = (" · " + "+".join(caps)) if caps else ""
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"LFI: {shown} ({len(pts)}){tail}"[:140]}

    # 2s) rfi-scan: wrapper inclusion with code execution (marker echoed) → RCE
    if sid == "rfi-scan":
        execs = re.findall(r"✗ RFI (\S+)", output)
        if not execs:
            return None
        shown = ", ".join(execs[:4]) + (f" +{len(execs) - 4}" if len(execs) > 4 else "")
        vtail = "; rev-shell verified" if "egress VERIFIED" in output else ""
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"RFI RCE (wrapper): {shown} ({len(execs)}){vtail}"[:140]}

    # 2t) cmdi-scan: OS command injection (computed-marker or time) → RCE
    if sid == "cmdi-scan":
        pts = re.findall(r"✗ CMDI (\S+)", output)
        if not pts:
            return None
        mu = re.search(r"^\s+id: (uid=\S+)", output, re.M)
        shown = ", ".join(pts[:4]) + (f" +{len(pts) - 4}" if len(pts) > 4 else "")
        tail = f" · {mu.group(1)}" if mu else ""
        if "egress VERIFIED" in output:
            tail += " · rev-shell verified"
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"OS cmd injection: {shown} ({len(pts)}){tail}"[:140]}

    # 2u) ssti-scan: template injection — RCE-confirmed (id) high, eval-only medium
    if sid == "ssti-scan":
        rce = re.findall(r"✗ SSTI (\S+)", output)
        eval_only = re.findall(r"⚠ SSTI (\S+)", output)
        if rce:
            eng = re.search(r"→ (\w+), RCE confirmed", output)
            uid = re.search(r"id: (uid=\S+)", output)
            shown = ", ".join(rce[:4]) + (f" +{len(rce) - 4}" if len(rce) > 4 else "")
            tail = (f"; {eng.group(1)}" if eng else "") + (f"; {uid.group(1)}" if uid else "")
            if "egress VERIFIED" in output:
                tail += "; rev-shell verified"
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SSTI RCE: {shown} ({len(rce)}){tail}"[:140]}
        if eval_only:
            shown = ", ".join(eval_only[:4]) + (f" +{len(eval_only) - 4}" if len(eval_only) > 4 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "MEDIUM",
                    "summary": f"SSTI (eval, RCE unconfirmed): {shown} ({len(eval_only)})"[:140]}
        return None

    # 2v) upload-shell: file-upload webshell — code-executed critical, merely-stored high
    if sid == "upload-shell":
        rce = re.findall(r"✗ UPLOAD (\S+)", output)
        stored = re.findall(r"⚠ UPLOAD (\S+)", output)
        if rce:
            var = re.search(r"✗ UPLOAD \S+\s+\(([^)]+)\)", output)
            vt = f" ({var.group(1)})" if var else ""
            shown = rce[0] + (f" +{len(rce) - 1}" if len(rce) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"File-upload RCE: {shown}{vt}"[:140]}
        if stored:
            shown = stored[0] + (f" +{len(stored) - 1}" if len(stored) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Arbitrary file upload (exec unconfirmed): {shown}"[:140]}
        return None

    # 2w) xxe-ssrf: metadata/file-read critical, OOB-confirmed SSRF/XXE high
    if sid == "xxe-ssrf":
        meta = re.findall(r"✗ SSRF-META (\S+)", output)
        s_oob = re.findall(r"✗ SSRF-OOB (\S+)", output)
        x_read = re.findall(r"✗ XXE-READ (\S+)", output)
        x_oob = re.findall(r"✗ XXE-OOB (\S+)", output)
        if x_read:
            shown = x_read[0] + (f" +{len(x_read) - 1}" if len(x_read) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"XXE file read: {shown}"[:140]}
        if meta:
            shown = meta[0] + (f" +{len(meta) - 1}" if len(meta) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"SSRF → cloud metadata: {shown}"[:140]}
        if s_oob or x_oob:
            bits = ([f"SSRF ({len(s_oob)})"] if s_oob else []) + ([f"XXE ({len(x_oob)})"] if x_oob else [])
            first = (s_oob or x_oob)[0]
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Out-of-band {' + '.join(bits)}: {first}"[:140]}
        return None

    # 2x) idor-bac: IDOR / broken access control / authz bypass high, enumerable-only info
    if sid == "idor-bac":
        idor = re.findall(r"✗ IDOR (\S+)", output)
        bac = re.findall(r"✗ BAC (\S+)", output)
        authz = re.findall(r"✗ AUTHZ-BYPASS (\S+)", output)
        enum = re.findall(r"⚠ ENUM (\S+)", output)
        if idor:
            authed = " [authenticated]" if "[authenticated as" in output else ""
            shown = idor[0] + (f" +{len(idor) - 1}" if len(idor) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"IDOR: {shown}{authed}"[:140]}
        if bac:
            shown = bac[0] + (f" +{len(bac) - 1}" if len(bac) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Broken access control (unauth): {shown}"[:140]}
        if authz:
            shown = authz[0] + (f" +{len(authz) - 1}" if len(authz) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"401/403 authz bypass: {shown}"[:140]}
        if enum:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Enumerable objects (verify for IDOR): {enum[0]}"[:140]}
        return None

    # 2y) cms-scan: vulnerable plugin/theme/core high, user enum info, detection info
    if sid == "cms-scan":
        vulns = re.findall(r"✗ CMS-VULN (.+)", output)
        users = re.search(r"⚠ CMS-USERS (.+)", output)
        cmsm = re.search(r"^CMS: (.+)$", output, re.M)
        if vulns:
            shown = vulns[0][:90] + (f" +{len(vulns) - 1}" if len(vulns) > 1 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"CMS vuln: {shown}"[:140]}
        if users:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"CMS user enumeration: {users.group(1)}"[:140]}
        if cmsm:
            return {"state": "INFO", "cve": cve, "risk": "INFO",
                    "summary": f"CMS detected: {cmsm.group(1)}"[:140]}
        return None

    # 2z) admin-rce: authenticated admin panel → code execution
    if sid == "admin-rce":
        hits = re.findall(r"✗ ADMIN-RCE (\S+)", output)
        if hits:
            meth = re.search(r"✗ ADMIN-RCE \S+\s+\(([^)]+)\)", output)
            mt = f" ({meth.group(1)})" if meth else ""
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Authenticated admin RCE: {hits[0]}{mt}"[:140]}
        return None

    # 2aa) foothold: a reverse shell was fired over a confirmed RCE channel
    if sid == "foothold":
        m = re.search(r"foothold: fired (.+)$", output)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Reverse shell foothold: {m.group(1)}"[:140]}
        return None

    # 2ab) smb-enum: SMB signing not required / SMBv1 → relay & EternalBlue surface (high);
    # null/guest sessions & readable shares → exposed; otherwise the OS/domain banner is info.
    if sid == "smb-enum":
        conds, state, risk = [], "INFO", "LOW"
        if "signing NOT required" in output:
            conds.append("SMB signing not required (NTLM relay)")
            state, risk = "VULNERABLE", "HIGH"
        if "SMBv1 enabled" in output:
            conds.append("SMBv1 enabled (EternalBlue surface)")
            state, risk = "VULNERABLE", "HIGH"
        acc = re.search(r"Access:\s*(null session|guest) allowed", output)
        if acc:
            conds.append(f"{acc.group(1)} allowed")
            if state == "INFO":
                state, risk = "EXPOSED", "MEDIUM"
        rsh = [m.group(1) for m in re.finditer(r"^\s*(\S+)\s+(?:READ,WRITE|READ|WRITE)\b", output, re.M)
               if m.group(1).upper() not in ("IPC$", "SHARE", "SHARENAME", "DISK")]
        if rsh:
            conds.append("readable shares: " + ", ".join(dict.fromkeys(rsh))[:60])
            if state == "INFO":
                state, risk = "EXPOSED", "MEDIUM"
        if conds:
            return {"state": state, "cve": cve, "risk": risk, "summary": (" · ".join(conds))[:140]}
        mo = re.search(r"OS:\s*(.+)", output)
        if mo:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": ("SMB: " + mo.group(1).strip())[:140]}
        return None

    # 2ac) smb-vuln: confirmed unauth version-RCE (MS17-010 / MS08-067 / SMBGhost / DoublePulsar)
    if sid == "smb-vuln":
        hits = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"SMB RCE: {shown}"[:140]}

    # 2ad) smb-loot: creds recovered from shares (highest) → secrets → sensitive file inventory
    if sid == "smb-loot":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        files = re.findall(r"^· FILE ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"SMB loot creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:3]) + (f" +{len(secrets) - 3}" if len(secrets) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"SMB loot secrets: {shown}"[:140]}
        if files:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"SMB readable shares: {len(files)} sensitive file(s)"[:140]}
        return None

    # 2az) ftp-foothold: a shell path was taken (backdoor / web-rce / ssh-key)
    if sid == "ftp-foothold":
        mm = re.search(r"^ftp-foothold: (\w[\w-]* shell → .+)$", output, re.M)
        if mm:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {mm.group(1)}"[:140]}
        return None

    # 2ay) ftp-bounce: internal-only ports reachable through the FTP server (PORT bounce)
    if sid == "ftp-bounce":
        op = re.findall(r"^✗ BOUNCE 127\.0\.0\.1:(\d+) open\s+\(([^)]+)\)", output, re.M)
        if not op:
            return None
        shown = ", ".join(f"{p} {h}" for p, h in op[:6])
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"FTP bounce → internal: {shown}"[:140]}

    # 2ax) ftp-webshell: FTP-writable dir served by a web root → code execution
    if sid == "ftp-webshell":
        rcehits = re.findall(r"^✗ RCE (.+)$", output, re.M)
        served = re.findall(r"^✗ SERVED (.+)$", output, re.M)
        if rcehits:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"FTP→web RCE: {rcehits[0].strip()}"[:140]}
        if served:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"FTP dir web-served: {served[0].strip()}"[:140]}
        return None

    # 2aw) ftp-creds: default / reused FTP login worked → immediate access
    if sid == "ftp-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"FTP creds: {shown}"[:140]}

    # 2av) ftp-write: anonymous-writable directory — webshell / payload-drop surface
    if sid == "ftp-write":
        w = re.findall(r"^✗ WRITABLE (\S+)", output, re.M)
        if not w:
            return None
        shown = ", ".join(dict.fromkeys(w))[:100]
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"anonymous-writable FTP dir(s): {shown}"[:140]}

    # 2au) ftp-anon: anonymous FTP access — high when it exposes interesting files
    if sid == "ftp-anon":
        if "anonymous login allowed" not in output:
            return None
        ni = len(re.findall(r"^! ", output, re.M))
        summ = "anonymous FTP login allowed" + (f" · {ni} interesting file(s)" if ni else "")
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if ni else "MEDIUM",
                "summary": summ[:140]}

    # 2bf) telnet-shell: an interactive telnet session was spawned (auto-login / no-auth)
    if sid == "telnet-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"telnet foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bq) mssql-loot: sql_login hashes / linked servers / file-read > db inventory
    if sid == "mssql-loot":
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        linked = re.findall(r"^✗ LINKED (\S+)", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        bits = []
        if hashes:
            bits.append(f"{len(hashes)} sql_login hash(es)")
        if linked:
            bits.append(f"linked: {', '.join(linked[:3])}")
        if fread:
            bits.append("OPENROWSET file-read")
        if bits:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MSSQL loot: {'; '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MSSQL: {len(dbs)} non-system database(s)"[:140]}
        return None

    # 2bp) mssql-shell: a PowerShell reverse shell was fired through xp_cmdshell
    if sid == "mssql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MSSQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bo) mssql-exec: xp_cmdshell command execution confirmed
    if sid == "mssql-exec":
        mo = re.search(r"^✗ EXEC .*running as (.+)$", output, re.M)
        if mo:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MSSQL xp_cmdshell RCE as {mo.group(1).strip()}"[:140]}
        return None

    # 2bn) mssql-creds: sa/default/reused login → DB access (sysadmin = command exec)
    if sid == "mssql-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        admin = any("sysadmin" in h for h in hits)
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL" if admin else "HIGH",
                "summary": f"MSSQL creds: {shown}"[:140]}

    # 2bw) ldap-loot: LAPS/gMSA creds (high) > description secrets > bloodhound
    if sid == "ldap-loot":
        laps = re.findall(r"^✗ LAPS (\S+)", output, re.M)
        gmsa = re.findall(r"^✗ GMSA (\S+)", output, re.M)
        descs = re.findall(r"^✗ DESC ", output, re.M)
        if laps or gmsa:
            bits = []
            if laps:
                bits.append(f"LAPS: {', '.join(laps[:3])}")
            if gmsa:
                bits.append(f"gMSA: {', '.join(gmsa[:3])}")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"AD loot — {'; '.join(bits)}"[:140]}
        if descs:
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"AD: {len(descs)} password(s) in description fields"[:140]}
        return None

    # 2bv) ldap-roast: AS-REP / Kerberoast hashes → offline crack to domain creds
    if sid == "ldap-roast":
        asrep = re.findall(r"^✗ ASREP (\S+)", output, re.M)
        tgs = re.findall(r"^✗ TGS (\S+)", output, re.M)
        if not asrep and not tgs:
            return None
        bits = []
        if asrep:
            bits.append(f"AS-REP: {', '.join(asrep[:3])}")
        if tgs:
            bits.append(f"Kerberoast: {', '.join(tgs[:3])}")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"roastable ({'; '.join(bits)})"[:140]}

    # 2bu) ldap-enum: anonymous AD enumeration (exposed) → else domain/user info
    if sid == "ldap-enum":
        if re.search(r"^✗ ANON ", output, re.M):
            mu = re.search(r"·\s*users:\s*(\d+)", output)
            extra = f" · {mu.group(1)} users" if mu else ""
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"LDAP anonymous enumeration allowed{extra}"[:140]}
        md = re.search(r"domain:\s*(\S+)", output)
        mu = re.search(r"·\s*users:\s*(\d+)", output)
        if md and md.group(1) != "?":
            summ = f"AD domain {md.group(1)}" + (f" · {mu.group(1)} users" if mu else "")
            return {"state": "INFO", "cve": None, "risk": "LOW", "summary": summ[:140]}
        return None

    # 2bt) ssh-shell: a direct SSH session was opened with a proven cred
    if sid == "ssh-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"SSH foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bs) ssh-creds: reused/default SSH login worked → direct shell access
    if sid == "ssh-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"SSH creds: {shown}"[:140]}

    # 2br) ssh-banner: libssh auth bypass (critical) → else version info
    if sid == "ssh-banner":
        vulns = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if vulns:
            vcve = ",".join(sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", " ".join(vulns))))) or None
            return {"state": "VULNERABLE", "cve": vcve, "risk": "CRITICAL",
                    "summary": f"SSH: {vulns[0]}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"SSH: {mv.group(1).strip()}"[:140]}
        return None

    # 2bm) mssql-banner: unauthenticated version disclosure (info)
    if sid == "mssql-banner":
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"MSSQL: {mv.group(1).strip()}"[:140]}
        return None

    # 2bl) mysql-shell: a reverse shell was fired through the OUTFILE webshell
    if sid == "mysql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MySQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bk) mysql-rce: INTO OUTFILE webshell → confirmed command execution
    if sid == "mysql-rce":
        if re.search(r"^✗ RCE ", output, re.M):
            mu = re.search(r"^✗ RCE (\S+)", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"MySQL RCE: webshell {mu.group(1)}"[:140]}
        return None

    # 2bj) mysql-loot: app creds > user hashes / file-read > db inventory
    if sid == "mysql-loot":
        appc = re.findall(r"^✗ CRED (.+)$", output, re.M)
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        if appc:
            shown = "; ".join(c.strip() for c in appc[:2]) + (f" +{len(appc) - 2}" if len(appc) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"MySQL app creds: {shown}"[:140]}
        if hashes or fread:
            bits = []
            if hashes:
                bits.append(f"{len(hashes)} mysql.user hash(es)")
            if fread:
                bits.append("LOAD_FILE /etc/passwd")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MySQL loot: {', '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MySQL: {len(dbs)} non-system database(s) readable"[:140]}
        return None

    # 2bi) mysql-creds: default/reused login or CVE-2012-2122 bypass → DB access
    if sid == "mysql-creds":
        if re.search(r"^✗ BYPASS ", output, re.M):
            return {"state": "VULNERABLE", "cve": "CVE-2012-2122", "risk": "CRITICAL",
                    "summary": "MySQL auth bypass (CVE-2012-2122) — root without a password"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"MySQL creds: {shown}"[:140]}

    # 2bh) mysql-banner: unauthenticated version disclosure (info)
    if sid == "mysql-banner":
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"MySQL: {mv.group(1).strip()}"[:140]}
        return None

    # 2bc6) rdp-shell: an interactive RDP desktop session was spawned
    if sid == "rdp-shell":
        if "desktop → " in output:
            mm = re.search(r"desktop → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"RDP foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bc5) rdp-creds: a reused/known cred authenticates over RDP (local admin → critical)
    if sid == "rdp-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        risk = "CRITICAL" if "local admin" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"RDP creds: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bc4) rdp-enum: MS12-020 / weak Standard-RDP-Security (exposed) → else info
    if sid == "rdp-enum":
        if re.search(r"^✗ MS12-020", output, re.M):
            return {"state": "VULNERABLE", "cve": "CVE-2012-0002", "risk": "HIGH",
                    "summary": "RDP MS12-020 (CVE-2012-0002) — pre-auth RCE/DoS"[:140]}
        if re.search(r"^✗ WEAK ", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": "RDP: Standard RDP Security (no NLA) — credential MITM surface"[:140]}
        mv = re.search(r"^· host:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"RDP: {mv.group(1).strip()}"[:140]}
        return None

    # 2bc3) vnc-shell: a VNC desktop session was spawned
    if sid == "vnc-shell":
        if "desktop → " in output:
            mm = re.search(r"desktop → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"VNC foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bc2) vnc-creds: a weak/reused VNC password worked
    if sid == "vnc-creds":
        if re.search(r"^✗ NOAUTH", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "VNC: open desktop, no password required"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"VNC password: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bc1) vnc-enum: 'None' security type = open desktop (critical) → else info
    if sid == "vnc-enum":
        if re.search(r"^✗ NOAUTH", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "VNC: 'None' security type — desktop open with no auth"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"VNC: {mv.group(1).strip()}"[:140]}
        return None

    # 2bd3) mongo-loot: credential-like fields dumped from collections
    if sid == "mongo-loot":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        colls = re.findall(r"^· coll ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:2]) + (f" +{len(creds) - 2}" if len(creds) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"MongoDB creds: {shown}"[:140]}
        if colls:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"MongoDB: {len(colls)} collection(s) readable unauthenticated"[:140]}
        return None

    # 2bd2) mongo-auth: default/reused login worked (or no auth needed)
    if sid == "mongo-auth":
        if re.search(r"^✗ UNAUTH", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": "MongoDB: no authentication required (remote read)"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"MongoDB creds: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2bd1) mongo-info: unauthenticated MongoDB (exposed) → else version disclosure (info)
    if sid == "mongo-info":
        if re.search(r"^✗ UNAUTH", output, re.M):
            mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"MongoDB unauthenticated: {(mv.group(1).strip() if mv else 'remote read')}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"MongoDB: {mv.group(1).strip()}"[:140]}
        return None

    # 2be6) redis-shell: reverse shell fired through the CONFIG-SET webshell
    if sid == "redis-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Redis foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2be5) redis-rce: CONFIG SET dir/dbfilename webshell → confirmed command execution
    if sid == "redis-rce":
        mu = re.search(r"^✗ RCE (\S+)", output, re.M)
        if mu:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"Redis RCE: webshell {mu.group(1)}"[:140]}
        return None

    # 2be4) redis-loot: leaked requirepass/masterauth or dumped key values
    if sid == "redis-loot":
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        keys = re.findall(r"^✗ KEY ", output, re.M)
        if secrets:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"Redis secret: {'; '.join(s.strip() for s in secrets[:2])}"[:140]}
        if keys:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"Redis: {len(keys)} key value(s) dumped (creds/sessions)"[:140]}
        return None

    # 2be3) redis-auth: a default/reused password (or unauth) unlocked Redis
    if sid == "redis-auth":
        if re.search(r"^✗ UNAUTH", output, re.M):
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": "Redis: no authentication required (remote read/write)"[:140]}
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Redis auth: {'; '.join(h.strip() for h in hits[:3])}"[:140]}

    # 2be2) redis-info: unauthenticated Redis (exposed) → else version disclosure (info)
    if sid == "redis-probe":
        if re.search(r"^✗ UNAUTH", output, re.M):
            mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"Redis unauthenticated: {(mv.group(1).strip() if mv else 'remote read/write')}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Redis: {mv.group(1).strip()}"[:140]}
        return None

    # 2bf3) krb-spray: Kerberos pre-auth spray validated a domain cred
    if sid == "krb-spray":
        hits = re.findall(r"^✗ CREDS (.+?)  \(Kerberos", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Kerberos creds: {shown}"[:140]}

    # 2bf2) krb-roast: AS-REP / Kerberoast hashes harvested over port 88
    if sid == "krb-roast":
        asrep = re.findall(r"^✗ ASREP ", output, re.M)
        tgs = re.findall(r"^✗ TGS ", output, re.M)
        if not (asrep or tgs):
            return None
        bits = []
        if asrep:
            bits.append(f"{len(asrep)} AS-REP")
        if tgs:
            bits.append(f"{len(tgs)} Kerberoast")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Kerberos roastable: {', '.join(bits)}"[:140]}

    # 2bf1) krb-enum: valid AD users enumerated without credentials
    if sid == "krb-enum":
        users = re.findall(r"^✗ USER (\S+)", output, re.M)
        if not users:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"Kerberos: {len(users)} valid AD user(s) enumerated ({', '.join(users[:4])})"[:140]}

    # 2bg4) oracle-creds: default/reused account worked → DB access (DBA flagged)
    if sid == "oracle-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        risk = "CRITICAL" if "(DBA)" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"Oracle creds: {shown}"[:140]}

    # 2bg3) oracle-sid: SID / service name discovered (needed to attack)
    if sid == "oracle-sid":
        sids = re.findall(r"^✗ SID (\S+)", output, re.M)
        if not sids:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"Oracle SID(s): {', '.join(sids[:6])}"[:140]}

    # 2bg2) oracle-tns: unauthenticated status leak (exposed) → else version disclosure (info)
    if sid == "oracle-tns":
        if re.search(r"^✗ STATUS leak", output, re.M):
            ml = re.search(r"exposed unauthenticated:\s*(.+)$", output, re.M)
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"Oracle TNS status leak: {(ml.group(1) if ml else '').strip()}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": f"Oracle: {mv.group(1).strip()}"[:140]}
        return None

    # 2bh6) psql-shell: a reverse shell was fired through COPY … FROM PROGRAM
    if sid == "psql-shell":
        if "shell → " in output:
            mm = re.search(r"shell → (.+)$", output, re.M)
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"PostgreSQL foothold — {mm.group(1).strip()}"[:140]}
        return None

    # 2bh5) psql-rce: COPY … FROM PROGRAM → confirmed command execution
    if sid == "psql-rce":
        if re.search(r"^✗ RCE ", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": "PostgreSQL RCE: COPY … FROM PROGRAM command exec"[:140]}
        return None

    # 2bh4) psql-loot: app creds > pg_shadow hashes / file-read > db inventory
    if sid == "psql-loot":
        appc = re.findall(r"^✗ CRED (.+)$", output, re.M)
        hashes = re.findall(r"^✗ HASH ", output, re.M)
        fread = re.search(r"^✗ FILE-READ ", output, re.M)
        dbs = re.findall(r"^· DB ", output, re.M)
        if appc:
            shown = "; ".join(c.strip() for c in appc[:2]) + (f" +{len(appc) - 2}" if len(appc) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"PostgreSQL app creds: {shown}"[:140]}
        if hashes or fread:
            bits = []
            if hashes:
                bits.append(f"{len(hashes)} pg_shadow hash(es)")
            if fread:
                bits.append("pg_read_file /etc/passwd")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"PostgreSQL loot: {', '.join(bits)}"[:140]}
        if dbs:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"PostgreSQL: {len(dbs)} non-system database(s) readable"[:140]}
        return None

    # 2bh3) psql-creds: default/reused login → DB access (superuser flagged)
    if sid == "psql-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        risk = "CRITICAL" if "(superuser)" in output else "HIGH"
        return {"state": "VULNERABLE", "cve": cve, "risk": risk,
                "summary": f"PostgreSQL creds: {shown}"[:140]}

    # 2bh2) psql-banner: trust auth (weakness) → else auth method / version disclosure (info)
    if sid == "psql-banner":
        if re.search(r"^✗ TRUST ", output, re.M):
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": "PostgreSQL trust auth — 'postgres' needs no password"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"PostgreSQL: {mv.group(1).strip()}"[:140]}
        ma = re.search(r"^\[\*\] Auth method:\s*(.+)$", output, re.M)
        if ma:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"PostgreSQL: auth {ma.group(1).strip()}"[:140]}
        return None

    # 2bg) telnet-sniff: cleartext telnet creds captured off the wire
    if sid == "telnet-sniff":
        hits = re.findall(r"^✗ SNIFF (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"telnet cleartext sniffed: {shown}"[:140]}

    # 2be) telnet-creds: default / reused telnet login worked → immediate access
    if sid == "telnet-creds":
        hits = re.findall(r"^✗ CREDS (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"telnet creds: {shown}"[:140]}

    # 2bd) telnet-banner: unauthenticated shell (critical) → else banner / auth-required info
    if sid == "telnet-banner":
        no = re.search(r"^✗ NOAUTH unauthenticated shell — (.+)$", output, re.M)
        if no:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"telnet: unauthenticated shell ({no.group(1)})"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"telnet: {mv.group(1).strip()}"[:140]}
        return None

    # 2bc) tftp-write: anonymous WRQ accepted — payload-drop / config-overwrite surface
    if sid == "tftp-write":
        w = re.findall(r"^✗ WRITABLE (\S+)", output, re.M)
        if not w:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"anonymous-writable TFTP (no DELETE): {w[0]}"[:140]}

    # 2bb) tftp-grab: creds/secrets pulled from world-readable device configs & boot files
    if sid == "tftp-grab":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        files = re.findall(r"^· FILE ", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP config creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:2]) + (f" +{len(secrets) - 2}" if len(secrets) > 2 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP config secrets: {shown}"[:140]}
        if files:
            return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                    "summary": f"TFTP: {len(files)} world-readable file(s) retrieved"[:140]}
        return None

    # 2ba) tftp-probe: path-traversal arbitrary read (critical) → else just a reachable TFTP server
    if sid == "tftp-probe":
        reads = re.findall(r"^✗ VULN arbitrary file read via path traversal — (.+?) readable$", output, re.M)
        if reads:
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"TFTP path-traversal read: {', '.join(reads[:4])}"[:140]}
        if "it's a TFTP server" in output:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": "TFTP/69 reachable — no auth, read/write primitive"[:140]}
        return None

    # 2at) ftp-banner: known-backdoor FTP version → critical RCE; else version info
    if sid == "ftp-banner":
        vulns = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if vulns:
            vcve = ",".join(sorted(set(re.findall(r"CVE-\d{4}-\d{3,7}", " ".join(vulns))))) or None
            return {"state": "VULNERABLE", "cve": vcve, "risk": "CRITICAL",
                    "summary": f"FTP: {vulns[0]}"[:140]}
        mv = re.search(r"^\[\*\] Service:\s*(.+)$", output, re.M)
        if mv:
            return {"state": "INFO", "cve": None, "risk": "LOW",
                    "summary": f"FTP: {mv.group(1).strip()}"[:140]}
        return None

    # 2as) winrm-recon: post-access recon — hot privilege → privesc path; pivot subnets
    if sid == "winrm-recon":
        privs = re.findall(r"^✗ PRIV (\S+)", output, re.M)
        if privs:
            hot = any(p in _HOT_PRIVS for p in privs)
            shown = ", ".join(privs[:5])
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH" if hot else "MEDIUM",
                    "summary": f"WinRM privileges: {shown}"[:140]}
        if "Networks:" in output:
            return {"state": "INFO", "cve": cve, "risk": "LOW",
                    "summary": "WinRM post-access recon (pivot surface)"[:140]}
        return None

    # 2ar) winrm-access: enumerated who can use WinRM (Remote Management Users / admins)
    if sid == "winrm-access":
        hits = [h.replace("  (have cred)", "").strip()
                for h in re.findall(r"^✗ WINRM-USER (.+)$", output, re.M)]
        if not hits:
            return None
        shown = ", ".join(dict.fromkeys(hits))[:110]
        return {"state": "EXPOSED", "cve": cve, "risk": "MEDIUM",
                "summary": f"WinRM access: {shown}"[:140]}

    # 2aq) winrm-shell: an interactive evil-winrm session was spawned over a WinRM cred
    if sid == "winrm-shell":
        m = re.search(r"^winrm-shell: (evil-winrm shell → .+)$", output, re.M)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {m.group(1)}"[:140]}
        return None

    # 2ap) winrm-spray: harvested creds valid on WinRM (reuse); a shell (Pwn3d!) is critical
    if sid == "winrm-spray":
        shell = re.findall(r"^✗ SHELL (.+?)\s{2}", output, re.M)
        valid = re.findall(r"^✓ VALID (.+)$", output, re.M)
        if shell:
            shown = "; ".join(s.strip() for s in shell[:3]) + (f" +{len(shell) - 3}" if len(shell) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"WinRM shell: {shown}"[:140]}
        if valid:
            shown = "; ".join(v.strip() for v in valid[:3]) + (f" +{len(valid) - 3}" if len(valid) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"valid WinRM creds: {shown}"[:140]}
        return None

    # 2ao) winrm-enum: WinRM transport confirmed → evil-winrm target; Basic-over-HTTP is worse
    if sid == "winrm-enum":
        trans = re.findall(r"((?:HTTPS?) \d+) ✓", output)
        if not trans:
            return None
        auth = re.search(r"Auth:\s*(.+)", output)
        risk = "HIGH" if "Basic auth over HTTP" in output else "MEDIUM"
        summ = f"WinRM: {', '.join(trans)}" + (f" · auth {auth.group(1)}" if auth else "")
        return {"state": "EXPOSED", "cve": cve, "risk": risk, "summary": summ[:140]}

    # 2an) smb-foothold: an interactive admin session was spawned over valid creds / a hash
    if sid == "smb-foothold":
        m = re.search(r"^smb-foothold: (\S+ shell → .+)$", output, re.M)
        if m:
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"foothold — {m.group(1)}"[:140]}
        return None

    # 2am) smb-writable: hash-capture LNK planted on a writable share → coerces browsers
    if sid == "smb-writable":
        hits = re.findall(r"^✗ PLANT (.+)$", output, re.M)
        if not hits:
            return None
        shown = ", ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"writable share — hash-capture LNK planted: {shown}"[:140]}

    # 2al) smb-dump: credential material dumped (SAM/LSA/LSASS) or the domain (DCSync/NTDS)
    if sid == "smb-dump":
        dc = re.findall(r"^✗ DCSYNC (.+)$", output, re.M)
        du = re.findall(r"^✗ DUMP (.+)$", output, re.M)
        if dc:
            shown = "; ".join(d.strip() for d in dc[:2])
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"DCSync — domain dumped: {shown}"[:140]}
        if du:
            shown = "; ".join(d.strip() for d in du[:2]) + (f" +{len(du) - 2}" if len(du) > 2 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"creds dumped: {shown}"[:140]}
        return None

    # 2ak) smb-exec: command execution confirmed over admin creds → shell channel ready
    if sid == "smb-exec":
        hits = re.findall(r"^✗ EXEC (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"code exec: {shown}"[:140]}

    # 2aj) smb-spray: harvested creds valid elsewhere (reuse) → local admin is critical
    if sid == "smb-spray":
        admin = re.findall(r"^✗ ADMIN (.+?)\s{2}", output, re.M)
        valid = re.findall(r"^✓ VALID (.+)$", output, re.M)
        if admin:
            shown = "; ".join(a.strip() for a in admin[:3]) + (f" +{len(admin) - 3}" if len(admin) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                    "summary": f"local admin via reuse: {shown}"[:140]}
        if valid:
            shown = "; ".join(v.strip() for v in valid[:3]) + (f" +{len(valid) - 3}" if len(valid) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"valid creds (reuse): {shown}"[:140]}
        return None

    # 2ai) smb-dccve: confirmed DC-takeover CVE (ZeroLogon / noPac / PrintNightmare)
    if sid == "smb-dccve":
        hits = re.findall(r"^✗ VULN (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:4]) + (f" +{len(hits) - 4}" if len(hits) > 4 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"DC takeover: {shown}"[:140]}

    # 2ah) smb-coerce: target coercible into authenticating to us → drives the relay
    if sid == "smb-coerce":
        hits = re.findall(r"^✗ COERCE (.+)$", output, re.M)
        if not hits:
            return None
        return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                "summary": f"coercible: {', '.join(h.strip() for h in hits[:5])}"[:140]}

    # 2ag) smb-relay: NTLM relayed to a signing-off host → SAM hashes dumped remotely
    if sid == "smb-relay":
        hits = re.findall(r"^✗ SAM (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "CRITICAL",
                "summary": f"NTLM relay → SAM: {shown}"[:140]}

    # 2af) smb-poison: NetNTLM hashes captured via LLMNR/NBT-NS poisoning → crack/relay
    if sid == "smb-poison":
        hits = re.findall(r"^✗ HASH (.+)$", output, re.M)
        if not hits:
            return None
        shown = "; ".join(h.strip() for h in hits[:3]) + (f" +{len(hits) - 3}" if len(hits) > 3 else "")
        return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                "summary": f"Captured NetNTLM: {shown}"[:140]}

    # 2ae) smb-gpp: creds recovered from SYSVOL/NETLOGON GPP (domain-wide, reusable) → high
    if sid == "smb-gpp":
        creds = re.findall(r"^✗ CRED (.+)$", output, re.M)
        secrets = re.findall(r"^✗ SECRET (.+)$", output, re.M)
        if creds:
            shown = "; ".join(c.strip() for c in creds[:3]) + (f" +{len(creds) - 3}" if len(creds) > 3 else "")
            return {"state": "VULNERABLE", "cve": cve, "risk": "HIGH",
                    "summary": f"GPP creds: {shown}"[:140]}
        if secrets:
            shown = "; ".join(s.strip() for s in secrets[:3]) + (f" +{len(secrets) - 3}" if len(secrets) > 3 else "")
            return {"state": "EXPOSED", "cve": cve, "risk": "HIGH",
                    "summary": f"SYSVOL secrets: {shown}"[:140]}
        return None

    # 3) info rules over -sC output
    low = output.lower()
    info = None
    if sid == "http-git":
        info = ("exposed .git repository", "MEDIUM")
    elif sid == "http-config-backup":
        info = ("exposed config/backup file", "MEDIUM")
    elif sid == "http-methods" and re.search(r"\b(PUT|DELETE|TRACE|CONNECT)\b", output):
        info = ("risky HTTP methods enabled", "LOW")
    elif sid in ("http-title", "http-ls") and "index of /" in low:
        info = ("directory listing enabled", "LOW")
    elif sid == "ssl-enum-ciphers" and re.search(r"least strength:\s*[C-F]", output):
        info = ("weak TLS ciphers", "MEDIUM")
    elif sid in ("smb-security-mode", "smb2-security-mode") and "not required" in low:
        info = ("SMB message signing not required", "MEDIUM")
    elif sid == "ssh-auth-methods" and "password" in low:
        info = ("SSH password authentication enabled", "INFO")
    if info:
        return {"state": "INFO", "cve": cve, "risk": info[1], "summary": info[0]}
    return None
