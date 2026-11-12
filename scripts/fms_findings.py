#!/usr/bin/env python3
"""FMS findings: turn the checks' text output into findings, the same way for the skill and the scanner.

fms_scan.py (the skill's one-command scan) imports this, and so can any program that runs these checks without
a model, so a finding reads the same wherever it comes from. Each parser reads one check's output:

  parse_logcheck(text, warnings)       fms_logcheck.py's full output (not --brief)
  parse_exposure(text), parse_services(text), parse_ports(text)   fms_exposure_check.py
  parse_settings(text), settings_findings(settings)               fms_admin_review.py
  parse_advisories(text, version), advisory_findings(found)       fms_advisories.py
  service_findings(services, advisories, warnings)                --services-json and fms_service_advisories.py --json

A finding is {source, code, detail, address, account, flags}; references/finding-templates.json gives each code
its priority, title, why and what to do. Every section a parser counts is compared with the total the check
printed, so a change in a check's wording is reported as a warning, not skipped.

This is a module: it's imported, never run. Standard library only.
"""
import re

# The flag that decides a finding's wording. SERVER-ITSELF comes first: 127.0.0.1 is a schedule, not an attacker.
RANK = ["SERVER-ITSELF", "POSSIBLE-COMPROMISE", "SIGNED-IN", "XDBC", "RATE", "MANY-ACCOUNTS", "MANY-FILES",
        "GENERIC/DEFAULT", "NEVER-SUCCEEDED", "BEFORE-ACCESS-LOG"]

FAILED = re.compile(r"^  (\S+)\s+n=(\d+)\s+peak10=(\d+)\s+accts=(\d+) (\[.*?\])(?: \+\d+ more)? files=(\d+) via=(\[.*?\])\s*(.*)$")

XDBC = re.compile(r"^  (\S+)\s+n=(\d+)\s+(\S+ \S+\.\.\S+ \S+) accts=(\[.*?\])\s*(.*)$")

ADMIN = re.compile(r"^\s+(\d+) (\S+)\s+(.+?) \((.*?)\)\s*(.*)$")

DOWNLOAD = re.compile(r"^  (\S+ \S+) (.+?)\s+reads=(\d+)\s+MB=([\d.]+)\s+tables=(\d+)\s*(.*)$")

ANSWERED = re.compile(r"^\s+ANSWERED\s+(\d+) (\S+)\s+(\S+) (\d+)")

BURST = re.compile(r"^\s+(\S+ \S+) (\S+)\s+calls=(\d+)\s+layouts=(\d+)\s+BURST")

PORT = re.compile(r"^  (\d+)\s+OPEN\s+(.*?)\s+\[(.*?)\]\s+<-- review")

ANY_PORT = re.compile(r"^  (\d+)\s+(OPEN|closed|filtered|error \(.*?\))\s+(.*?)\s+\[(.*?)\](\s+<-- review)?\s*$")

WEB = re.compile(r"^  (\S+)\s+(/\S*)\s+(.*?)\s+<-- (.*)$")

def plural(n, word, words=None):
    return f"{n} {word if n == 1 else words or word + 's'}"

def finding(source, code, detail, address="", account="", flags=""):
    return {"source": source, "code": code, "detail": detail, "address": address, "account": account,
            "flags": flags or code}

def sections(text):
    """Split check output on its '## ' headings: [(heading, [lines])]."""
    found, current = [], None
    for line in text.splitlines():
        if line.startswith("## "):
            current = (line[3:], [])
            found.append(current)
        elif current:
            current[1].append(line)
    return found

def parse_logcheck(text, warnings):
    findings = []
    for heading, body in sections(text):
        if heading.startswith("Failed FileMaker sign-ins"):
            m = re.search(r"from (\d+) addresses", heading)
            parsed = 0
            for line in body:
                f = FAILED.match(line)
                if not f:
                    continue
                parsed += 1
                ip, n, peak, accts, names, files, via, flags = f.groups()
                code = next((c for c in RANK if c in flags), "FAILED-SIGN-IN")
                findings.append(finding("logs", code, f"{n} failed sign-ins, peak {peak} in 10 minutes, {accts} account "
                                        f"names {names}, {files} files, via {via}. {flags}".strip(), ip, names, flags))
            if m and int(m.group(1)) != parsed:
                warnings.append(f"Failed sign-ins: the check reported {m.group(1)} addresses, {parsed} were read")
        elif heading.startswith("ODBC/JDBC connections"):
            m = re.search(r"from (\d+) addresses", heading)
            parsed = 0
            for line in body:
                f = XDBC.match(line)
                if f:
                    parsed += 1
                    findings.append(finding("logs", "XDBC-CONNECTION", f"{f.group(2)} ODBC/JDBC connections, {f.group(3)}, "
                                            f"accounts {f.group(4)} {f.group(5)}".strip(), f.group(1), f.group(4),
                                            f.group(5) or "XDBC-CONNECTION"))
            if m and int(m.group(1)) != parsed:
                warnings.append(f"ODBC/JDBC: the check reported {m.group(1)} addresses, {parsed} were read")
        elif heading.startswith("Client versions"):
            for line in body:
                if "UPDATE:" in line:
                    findings.append(finding("logs", "CLIENT-UPDATE", line.strip()))
        elif heading.startswith("Admin Console / fmsadmin sign-ins"):
            for line in body:
                f = ADMIN.match(line)
                if f and f.group(5):
                    code = "ADMIN-NEW" if "NEW" in f.group(5) else "ADMIN-GENERIC"
                    findings.append(finding("logs", code, f"{f.group(1)} Admin Console sign-ins as {f.group(3)} "
                                            f"({f.group(4)}) {f.group(5)}".strip(), f.group(2), f.group(3), f.group(5)))
        elif heading.startswith("Admin sign-in failures"):
            for ip, n in re.findall(r"'([^']+)': (\d+)", heading):
                findings.append(finding("logs", "ADMIN-FAILED", f"{n} failed Admin Console sign-ins", ip))
        elif heading.startswith("Record downloads"):
            for line in body:
                f = DOWNLOAD.match(line)
                if f and re.search(r"HIGH-VOLUME|WIDE", f.group(6)):
                    code = "HIGH-VOLUME" if "HIGH-VOLUME" in f.group(6) else "WIDE"
                    # The client reads "account (machine) [address]". The check cuts it at 50 characters, which can lose the address.
                    who = f.group(2).strip()
                    address = (re.findall(r"\[([^\]\s]+)\]", who) or [""])[-1]
                    if not address:
                        warnings.append(f"A {code} finding has no address, because the client name is too long: {who}. Mark it Accepted once you know who it is")
                    findings.append(finding("logs", code, f"{f.group(1)}: {f.group(3)} reads, {f.group(4)} MB, {f.group(5)} "
                                            f"tables, {who} {f.group(6)}".strip(), address, who, f.group(6)))
        elif heading.startswith("Web server"):
            for line in body:
                f = ANSWERED.match(line)
                if f:
                    findings.append(finding("logs", "PHP-XML-ANSWERED", f"{f.group(1)} requests to {f.group(3)} answered {f.group(4)}", f.group(2)))
                f = BURST.match(line)
                if f:
                    findings.append(finding("logs", "BURST", f"{f.group(1)}: {f.group(3)} record calls across {f.group(4)} layouts", f.group(2)))
    return findings

def parse_exposure(text):
    findings = []
    for line in text.splitlines():
        f = PORT.match(line)
        if f:
            findings.append(finding("exposure", "PORT-OPEN", f"Port {f.group(1)} is open: {f.group(2)} [{f.group(3)}]"))
            continue
        f = WEB.match(line)
        if f:
            note = f.group(4)
            code = ("FILE-LIST-OPEN" if "LISTS" in note else
                    "SIGN-IN-PAGE-OPEN" if "sign-in page" in note else
                    "PHP-ON" if "PHP" in note else
                    "XML-ON" if "XML" in note else "EXPOSURE-CHECK")
            findings.append(finding("exposure", code, f"{f.group(2)} answered {f.group(1)}: {note}"))
        elif line.startswith("## Certificate") and re.search(r"NOT TRUSTED|could not read|<--", line):
            findings.append(finding("exposure", "CERTIFICATE", line[3:]))
        elif line.startswith("## HTTP") and re.search(r"no redirect|not redirect|answers", line, re.I):
            findings.append(finding("exposure", "HTTP-NO-REDIRECT", line[3:]))
        elif line.startswith("## HSTS") and "OFF" in line:
            findings.append(finding("exposure", "HSTS-OFF", line[3:].replace("  <-- turn on HSTS", "")))
        elif line.startswith("## Old TLS") and "ACCEPTS" in line:
            findings.append(finding("exposure", "TLS-OLD", line[3:].replace("  <-- turn off TLS 1.0 and 1.1", "")))
    return findings

# The settings review prints "  LEVEL  Area           text", the level 6 wide and the area 14 wide
SETTING_LEVELS = ("PASS", "FAIL", "REVIEW", "INFO")

# Areas the scan already judges elsewhere: the version through published issues, the certificate and services
# from the internet check. They stay in the settings list, but aren't raised again as findings.
SETTING_ELSEWHERE = {"Version", "Advisories", "Certificate", "Services"}

def parse_settings(text):
    """Every line of the settings review, and the paths it couldn't read."""
    settings = []
    for line in text.splitlines():
        if line[2:8].strip() in SETTING_LEVELS:
            settings.append({"level": line[2:8].strip(), "area": line[9:23].strip(), "text": line[24:].strip()})
        elif line.startswith("  -      /"):
            settings.append({"level": "NOT READ", "area": line[9:].split()[0], "text": line[9:].split(None, 1)[1].strip()
                             if len(line[9:].split(None, 1)) > 1 else ""})
    return settings

# Areas the review reports once per hosted file. A server with 35 files would raise 70 findings, so each area is one.
PER_FILE = ("File access", "Encryption")

def settings_findings(settings):
    raised, per_file = [], {}
    for s in settings:
        if s["level"] not in ("FAIL", "REVIEW") or s["area"] in SETTING_ELSEWHERE:
            continue
        if s["area"] in PER_FILE:
            per_file.setdefault((s["level"], s["area"]), []).append(s["text"])
        else:
            raised.append(finding("settings", "SETTING-" + s["level"], f"{s['area']}: {s['text']}", flags=s["area"]))
    for (level, area), texts in per_file.items():
        if area == "Encryption":
            detail = f"{plural(len(texts), 'hosted file')} not encrypted at rest: " + ", ".join(t.split(":")[0] for t in texts)
        else:
            # "Sales.fmp12: ODBC/JDBC, Data API access enabled in at least one privilege set; ..." as "Sales.fmp12 (ODBC/JDBC, Data API)"
            each = [re.sub(r"^(\S+): (.*?) access enabled.*$", r"\1 (\2)", t) for t in texts]
            detail = f"{plural(len(texts), 'hosted file')} with API or ODBC/JDBC access in at least one privilege set: " + ", ".join(each)
        raised.append(finding("settings", "SETTING-" + level, f"{area}: {detail}", flags=area))
    return raised

ISSUE = re.compile(r"^  (\d+(?:\.\d)?|-)\s+(\S+)\s+(fixed in .*)$")

def parse_advisories(text, version):
    """The published issues that affect this version, from fms_advisories.py's report."""
    found = {"version": version, "source": "", "behind": "", "issues": []}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("##### Source:"):
            found["source"] = line[len("##### Source:"):].strip()
        elif line.strip().startswith("Behind the latest"):
            found["behind"] = line.strip()
        else:
            m = ISSUE.match(line)
            if m:
                summary = lines[i + 1].strip() if i + 1 < len(lines) and lines[i + 1].startswith("       ") else ""
                if len(summary) >= 150:   # the skill's report cuts each summary at 150 characters
                    summary = summary.rstrip(" ,.;") + "…"
                url = lines[i + 2].strip() if i + 2 < len(lines) and lines[i + 2].startswith("       http") else ""
                found["issues"].append({"score": m.group(1), "id": m.group(2), "fixed": m.group(3), "summary": summary, "url": url})
    return found

def advisory_findings(found):
    out = []
    for x in found["issues"]:
        score = float(x["score"]) if x["score"] != "-" else 0
        code = "ADVISORY-CRITICAL" if score >= 9 else "ADVISORY-HIGH" if score >= 7 else "ADVISORY"
        out.append(finding("advisories", code, f"{x['id']}" + (f" (CVSS {x['score']})" if score else "")
                           + f", {x['fixed']}: {x['summary']}", flags=x["id"]))
    if found["behind"] and not found["issues"]:
        out.append(finding("advisories", "VERSION-BEHIND", f"FileMaker Server {found['version']}: {found['behind']}"))
    return out

# A published issue's severity, from NVD's CVSS score or Ubuntu's own priority, and the finding it raises
SERVICE_CVE = {"Critical": "SERVICE-CVE-CRITICAL", "High": "SERVICE-CVE-HIGH"}

SEVERITY_WORDS = {"SERVICE-CVE-CRITICAL": "rated Critical", "SERVICE-CVE-HIGH": "rated High",
                  "SERVICE-CVE": "rated Medium or Low"}

def service_label(s):
    return " ".join(x for x in (s.get("product"), s.get("version")) if x) or "not identified"

def service_findings(services, advisories, warnings):
    """Findings from what each open port said before sign-in, and the published issues for it and the OS."""
    out = []
    for s in services:
        p, label = s["port"], service_label(s)
        if s.get("no_auth"):
            out.append(finding("services", "VNC-NO-PASSWORD", f"Port {p}, {label}: asks for no password, so anyone "
                               "who connects gets the screen", flags=str(p)))
        if s.get("nla") is False:
            why = ("Network Level Authentication is off, so the sign-in screen is shown to anyone before they authenticate"
                   if "NETWORK LEVEL" in s.get("note", "") else "it uses old RDP security, with no TLS")
            out.append(finding("services", "RDP-NO-NLA", f"Port {p}, {label}: {why}", flags=str(p)))
        if s.get("version") == "SMB1 only":
            out.append(finding("services", "SMB1", f"Port {p}: file sharing only speaks SMB1, which Microsoft retired "
                               "and the WannaCry worm spread through", flags=str(p)))
    # A version in a greeting or header tells an attacker which published issues to try. Windows builds from NTLM
    # and VNC's protocol version aren't counted: the names finding covers NTLM, and RFB numbers name no product.
    shown = [s for s in services if s.get("version") and s.get("said") and not s.get("names")
             and s["version"] != "SMB1 only" and not s["version"].startswith("RFB")]
    if shown:
        out.append(finding("services", "SERVICE-VERSION-SHOWN",
                           f"{plural(len(shown), 'service')} give{'s' if len(shown) == 1 else ''} away "
                           f"{'its' if len(shown) == 1 else 'their'} version before sign-in: "
                           + ", ".join(f"{s['port']} {service_label(s)}" for s in shown), flags="version"))
    named = [s for s in services if s.get("names")]
    if named:
        names = []
        for s in named:
            for k in ("netbios_computer", "dns_computer", "netbios_domain", "dns_domain"):
                v = s["names"].get(k, "")
                if v and v.lower() not in (n.lower() for n in names):
                    names.append(v)
        out.append(finding("services", "SERVICE-NAMES-SHOWN",
                           ", ".join(f"{s['product']} ({s['port']})" for s in named)
                           + f" give{'s' if len(named) == 1 else ''} away the computer and domain names before sign-in: "
                           + ", ".join(names), flags="names"))
    for e in advisories.get("services", []):
        if e.get("source", "").startswith("couldn't"):
            warnings.append(f"Published issues for port {e['port']}, {e['product']}, {e['source']}")
            continue
        bands = {}
        for i in e.get("issues", []):
            bands.setdefault(SERVICE_CVE.get(i.get("severity"), "SERVICE-CVE"), []).append(i)
        ubuntu = e.get("source", "").startswith("Ubuntu")
        for code in ("SERVICE-CVE-CRITICAL", "SERVICE-CVE-HIGH", "SERVICE-CVE"):
            issues = bands.get(code)
            if not issues:
                continue
            ids = ", ".join(i["id"] + (f" ({i['cvss']})" if i.get("cvss") is not None else "") for i in issues[:6])
            ids += f" and {len(issues) - 6} more" if len(issues) > 6 else ""
            fixed = sum(1 for i in issues if i.get("fixed"))
            if ubuntu:
                which = ("It's" if len(issues) == 1 else "All of them are") if fixed == len(issues) else \
                    f"{fixed} of them {'is' if fixed == 1 else 'are'}"
                tail = (f" {which} fixed in a newer package"
                        + (f"; the newest fix is {e['update_to']}." if e.get("update_to") else ".") if fixed
                        else f" Ubuntu hasn't released a fix for {'it' if len(issues) == 1 else 'these'} yet.")
                if any(i.get("status") == "fixed only in Ubuntu Pro" for i in issues):
                    tail += " Some of those fixes come only with Ubuntu Pro."
                tail += f" From {e['source']}."
            else:
                tail = (" From NVD, by version: some apply only when a module or option is on, which can't be seen "
                        "from outside.")
            out.append(finding("services", code, f"Port {e['port']}, {e['product']}: {plural(len(issues), 'published issue')} "
                               f"{SEVERITY_WORDS[code]}: {ids}.{tail}", flags=f"{e['port']} {e['product']}"))
    support = advisories.get("os_support") or {}
    name, release = support.get("name", ""), support.get("release", "")
    system = release if release.startswith(name) else f"{name} {release}".strip()   # Ubuntu 22.04, Windows Server 2012 R2
    if support.get("state") in ("unsupported", "esm"):
        out.append(finding("services", "OS-UNSUPPORTED" if support["state"] == "unsupported" else "OS-EXTENDED",
                           support["text"], flags=system))
    return out

PATH_LINE = re.compile(r"^  (\S+)\s+(/\S*)\s+(.*)$")

# The web services FileMaker can turn off, and the exposure check's path that shows each one answering.
# FileMaker judges each against the server's intended services, so these are raised for every scan.
SERVICES = [("Data API", "/fmi/data/vLatest/productInfo", ("200",)),
            ("OData", "/fmi/odata/v4", ("200", "401")),
            ("WebDirect", "/fmi/webd/", ("200",))]

def parse_services(text):
    """One SERVICE-ON finding for each web service that answered. flags holds the service's name."""
    seen = {}
    for heading, body in sections(text):
        if heading.startswith("Web paths"):
            for line in body:
                m = PATH_LINE.match(line)
                if m:
                    seen[m.group(2)] = m.group(1)
    return [finding("exposure", "SERVICE-ON", f"{name} answers: GET {path} gave HTTP {seen[path]}", flags=name)
            for name, path, on in SERVICES if seen.get(path) in on]

def parse_ports(text):
    """Every port the exposure check tried, open or not, from its Ports section."""
    for heading, body in sections(text):
        if heading.startswith("Ports"):
            found = (ANY_PORT.match(line) for line in body)
            return [{"port": int(m.group(1)), "state": m.group(2), "service": m.group(3), "expected": m.group(4),
                     "review": 1 if m.group(5) else 0} for m in found if m]
    return []
