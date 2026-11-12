#!/usr/bin/env python3
"""FMS scan: every automated check of one FileMaker Server in one command, with a short summary.

Runs, in order, and saves each full output in the out folder:
  1. fms_exposure_check.py <host> --services-json   what the internet can reach, and what each open port says
  2. fms_service_advisories.py                      published issues for those services, and OS support
  3. fms_advisories.py <version>                    published issues for FileMaker Server, when the version is known
  4. fms_logcheck.py <logs> <since> --save          the log review, when logs are given

Then it turns the outputs into findings (fms_findings.py, shared with any program that runs these checks), judges the
FileMaker web services and ports 443 and 5003 against --intended, and writes:
  findings.json     every finding with its priority, title, why and what to do
  report-draft.md   the report in references/report-format.md's layout, with what the checks can't know marked TODO
  summary.txt       what this script prints: about 3 KB, so an Agent reads that instead of the full outputs

Usage:
    python3 fms_scan.py <hostname> [--logs <zip or folder>] [--since "YYYY-MM-DD HH:MM"] [--version <FMS version>]
                        [--intended "FileMaker Pro and Go, WebDirect"] [--out <folder>] [--no-exposure] [--offline]

  --since      default: everything in the logs (the log check alone defaults to the last 24 hours)
  --intended   the services the server is meant to offer, from intake: FileMaker Pro and Go, WebDirect, Data API,
               OData, ODBC/JDBC, XML, PHP, Admin Console, Admin API. Without it, every web service and open
               FileMaker web port is questioned
  --out        default: fms-scan-<hostname>-<date> in the current folder
  --offline    nothing looked up online (also FMS_SCANNER_OFFLINE)

Read-only, like each check it runs. Standard library only.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fms_findings import (parse_logcheck, parse_exposure, parse_services, parse_ports, parse_advisories,  # noqa: E402
                          advisory_findings, service_findings, finding, plural)

TEMPLATES = os.path.join(HERE, "..", "references", "finding-templates.json")
TIMEOUT = 1800   # seconds for one check; the largest log set seen so far (215 MB) took under a minute
ORDER = {"Critical": 1, "High": 2, "Medium": 3, "Check": 4, "Low": 5}
EMOJI = {"Critical": "🔴 Critical", "High": "🟠 High", "Medium": "🟡 Medium", "Check": "🔵 Check", "Low": "⚪ Low"}
# Intended services as intake names them, and the web service each one accepts (SERVICE-ON names these)
SERVICE_NAMES = ["FileMaker Pro and Go", "WebDirect", "Data API", "OData", "ODBC/JDBC", "XML", "PHP", "Admin Console", "Admin API"]
# Port 443 is needed by any web service; 5003 by FileMaker Pro and Go. Other open ports are judged by the
# exposure check itself (PORT-OPEN), whatever is intended.
NEEDS_443 = {"WebDirect", "Data API", "OData", "XML", "PHP", "Admin Console", "Admin API"}


def arg(args, name, default=""):
    return args[args.index(name) + 1] if name in args[:-1] else default


def run(script, args, path):
    """Run one check into a file. Returns (exit code, seconds, stderr tail)."""
    start = time.monotonic()
    with open(path, "w", encoding="utf-8") as out:
        try:
            done = subprocess.run([sys.executable, "-I", "-u", os.path.join(HERE, script), *args], stdout=out,
                                  stderr=subprocess.PIPE, text=True, timeout=TIMEOUT)
            return done.returncode, round(time.monotonic() - start), done.stderr.strip()[-300:]
        except subprocess.TimeoutExpired:
            return -1, TIMEOUT, "timed out"


def intended_list(text):
    """'filemaker pro, webdirect' -> ['FileMaker Pro and Go', 'WebDirect']: matched loosely, in the standard names."""
    t = text.lower()
    alias = {"FileMaker Pro and Go": r"filemaker pro|filemaker go|\bfmp\b|\bpro and go\b", "ODBC/JDBC": r"odbc|jdbc"}
    return [n for n in SERVICE_NAMES if n.lower() in t or (n in alias and re.search(alias[n], t))]


def judge_intended(findings, ports, intended):
    """Accept web services that are intended, and question an open 443 or 5003 nothing intended needs."""
    kept = [f for f in findings if not (f["code"] == "SERVICE-ON" and f["flags"] in intended)]
    accepted = [f["flags"] for f in findings if f["code"] == "SERVICE-ON" and f["flags"] in intended]
    opened = {p["port"] for p in ports if p["state"] == "OPEN"}
    if 443 in opened and not NEEDS_443 & set(intended):
        kept.append(finding("exposure", "PORT-NOT-INTENDED", "Port 443 is open, but no intended service needs it"))
    if 5003 in opened and "FileMaker Pro and Go" not in intended:
        kept.append(finding("exposure", "PORT-NOT-INTENDED", "Port 5003 is open, but FileMaker Pro and Go aren't intended"))
    return kept, accepted


def verdict(findings, logs_read):
    if not logs_read:
        return "Logs not read"
    weighs = {f.get("weighs") for f in findings}
    return ("Possible compromise" if "Compromise" in weighs else "Attempted attack" if "Attempted" in weighs
            else "No sign of attack")


def short(text, n=150):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n - 1] + "…"


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        sys.exit(__doc__)
    host = args[0].replace("https://", "").replace("http://", "").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        sys.exit("That isn't a plain hostname.")
    logs, since = arg(args, "--logs"), arg(args, "--since", "2020-01-01 00:00")
    version, intended = arg(args, "--version"), intended_list(arg(args, "--intended"))
    offline = "--offline" in args or bool(os.environ.get("FMS_SCANNER_OFFLINE"))
    out = arg(args, "--out") or f"fms-scan-{host}-{time.strftime('%Y-%m-%d')}"
    os.makedirs(out, mode=0o700, exist_ok=True)
    with open(TEMPLATES, encoding="utf-8") as f:
        templates = {t["code"]: t for t in json.load(f)}
    ran, warnings, findings, ports, system, svc_adv, adv, exposure_lines = {}, [], [], [], {}, {}, {}, []
    p = lambda name: os.path.join(out, name)   # noqa: E731

    if "--no-exposure" not in args:
        print(f"Checking what the internet can reach on {host} (about a minute)...", file=sys.stderr)
        ran["exposure"] = run("fms_exposure_check.py", [host, "--services-json", p("services.json")], p("exposure.txt"))
        text = open(p("exposure.txt"), encoding="utf-8").read()
        exposure_lines = exposure_headlines(text)
        findings += parse_exposure(text) + parse_services(text)
        ports = parse_ports(text)
        if os.path.exists(p("services.json")):
            scan = json.load(open(p("services.json"), encoding="utf-8"))
            system, version = scan.get("os") or {}, version or scan.get("fms_version", "")
            ran["services"] = run("fms_service_advisories.py", [p("services.json"), "--json", p("service-advisories.json")]
                                  + (["--offline"] if offline else []), p("service-advisories.txt"))
            if os.path.exists(p("service-advisories.json")):
                svc_adv = json.load(open(p("service-advisories.json"), encoding="utf-8"))
            findings += service_findings(scan.get("services", []), svc_adv, warnings)
    if version:
        ran["advisories"] = run("fms_advisories.py", [version] + (["--offline"] if offline else []), p("advisories.txt"))
        adv = parse_advisories(open(p("advisories.txt"), encoding="utf-8").read(), version)
        findings += advisory_findings(adv)
    if logs:
        print("Reading the logs...", file=sys.stderr)
        ran["logs"] = run("fms_logcheck.py", [os.path.expanduser(logs), since, "--brief", "--save", p("logcheck.txt")],
                          p("logcheck-brief.txt"))
        if os.path.exists(p("logcheck.txt")):
            findings += parse_logcheck(open(p("logcheck.txt"), encoding="utf-8").read(), warnings)
    findings, accepted = judge_intended(findings, ports, intended)
    for name, (code, secs, err) in ran.items():
        if code != 0:
            warnings.append(f"The {name} check didn't finish (exit {code}): {err[:200]}")
    for f in findings:
        t = templates.get(f["code"], {})
        # A code with no template stays visible as something to check, and counts as an attempt, never lower
        f.update(priority=t.get("priority", "Check"), weighs=t.get("weighs", "Attempted"), title=t.get("title", f["code"]),
                 why=t.get("why", ""), todo=t.get("todo", ""))
    findings.sort(key=lambda f: (ORDER.get(f["priority"], 9), f["code"]))
    logs_files = []
    if logs and os.path.exists(p("logcheck.txt")):
        m = re.search(r"^Files: (.*)$", open(p("logcheck.txt"), encoding="utf-8").read(), re.M)
        logs_files = m.group(1).split(", ") if m else []
    result = {"host": host, "checked": time.strftime("%Y-%m-%d %H:%M"), "verdict": verdict(findings, bool(logs_files)),
              "intended": intended, "accepted_services": accepted, "fms_version": version, "logs": logs, "since": since,
              "logs_files": logs_files, "ran": {k: {"exit": v[0], "seconds": v[1]} for k, v in ran.items()},
              "ports": ports, "os": system, "os_support": svc_adv.get("os_support", {}), "advisories": adv,
              "exposure": exposure_lines, "warnings": warnings, "findings": findings}
    write_findings(p("findings.json"), result, templates)
    with open(p("report-draft.md"), "w", encoding="utf-8") as f:
        f.write(draft(result, svc_adv))
    text = summary(result, os.path.abspath(out))
    with open(p("summary.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    print(text)


def exposure_headlines(text):
    """The lines of the exposure check worth seeing without opening it: redirect, certificate, HSTS, old TLS, the
    web paths that answered, the services and the OS."""
    keep, section = [], ""
    for line in text.splitlines():
        if line.startswith("## "):
            section = line
            if re.match(r"## (HTTP|Certificate|HSTS|Old TLS|FileMaker Server version|OS )", line):
                keep.append(line[3:])
        elif section.startswith("## Web paths") and re.match(r"^  (200|401|403)\s", line):
            keep.append("web " + " ".join(line.split()))
        elif section.startswith("## Services") and line.startswith("  ") and "no open ports" not in line:
            keep.append("service " + " ".join(line.split()))
    return keep


def write_findings(path, result, templates):
    """findings.json for searching, not reading: each finding on one line, the wording once per code."""
    keys = ("priority", "code", "address", "account", "detail", "flags", "source")
    lines = [json.dumps({k: f.get(k, "") for k in keys}, ensure_ascii=False) for f in result["findings"]]
    head = {k: v for k, v in result.items() if k != "findings"}
    used = {f["code"] for f in result["findings"]}
    head["wording"] = {c: {k: templates[c][k] for k in ("title", "why", "todo")} for c in sorted(used) if c in templates}
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(head, ensure_ascii=False)[:-1] + ', "findings": [\n' + ",\n".join(lines) + "\n]}\n")


def groups(findings):
    """Findings of one code together, in priority order: [(code, [findings])]."""
    out = {}
    for f in findings:
        out.setdefault(f["code"], []).append(f)
    return list(out.items())


def summary(r, out):
    fs = r["findings"]
    counts = {k: sum(1 for f in fs if f["priority"] == k) for k in ORDER}
    lines = [f"##### FMS scan: {r['host']}, {r['checked']}",
             f"Result: {r['verdict']}" + (" (before the addresses below are confirmed)" if r["verdict"] in
                                          ("Possible compromise", "Attempted attack") else ""),
             "Findings: " + " · ".join(f"{n} {k}" for k, n in counts.items() if n) if fs else "Findings: none",
             "Ran: " + ", ".join(f"{k} ({v['seconds']} s{'' if v['exit'] == 0 else ', FAILED'})" for k, v in r["ran"].items())]
    if r["ports"]:
        opened = [str(x["port"]) for x in r["ports"] if x["state"] == "OPEN"]
        lines.append(f"Ports: {len(r['ports'])} tried, open: {', '.join(opened) or 'none'}")
    if r["os"].get("name") or r["ports"]:
        lines.append("OS: " + (r["os_support"].get("text") or r["os"].get("name") or "not identified from outside"))
    if r.get("exposure"):
        lines.append("\n## What the internet sees (the rest is in exposure.txt)")
        lines += [f"  {short(x, 160)}" for x in r["exposure"]]
        lines.append("")
    if r["fms_version"]:
        lines.append(f"FileMaker Server {r['fms_version']}: {plural(len(r['advisories'].get('issues', [])), 'published issue')}"
                     + (f" ({r['advisories']['source']})" if r["advisories"].get("source") else ""))
    if r["accepted_services"]:
        lines.append("Intended and answering: " + ", ".join(r["accepted_services"]))
    if r["logs_files"]:
        lines.append(f"Logs read: {', '.join(r['logs_files'])}")
    lines.append("\n## Findings by kind (grep findings.json for a code or an address; one finding per line)")
    for code, fl in groups(fs):
        f = fl[0]
        lines.append(f"  {f['priority']:8} {code} x{len(fl)}: {short(f['title'], 90)}")
        for x in fl[:2 if f["priority"] in ("Critical", "High") else 1]:
            lines.append(f"           {short((x['address'] + ' ' if x['address'] else '') + x['detail'], 130)}")
    who = [f for f in fs if f["source"] == "logs" and f["address"] and f["weighs"] in ("Compromise", "Attempted")]
    if who:
        seen, rows = set(), []
        for f in who:
            if f["address"] not in seen:
                seen.add(f["address"])
                rows.append(f"  {f['address']:40} {f['code']}: {short(f['detail'], 80)}")
        lines.append(f"\n## Addresses to confirm with the user ({len(rows)}, worst first)")
        lines += rows[:12] + ([f"  and {len(rows) - 12} more in findings.json"] if len(rows) > 12 else [])
    if r["warnings"]:
        lines.append("\n## Warnings")
        lines += [f"  {short(w, 200)}" for w in r["warnings"]]
    lines.append(f"\nSaved in {out}/ (use this full path): report-draft.md, findings.json, and each check's full output "
                 "(exposure.txt, service-advisories.txt, advisories.txt, logcheck.txt).")
    lines.append("Next: confirm the addresses with the user, add the intake answers, then finish report-draft.md "
                 "(every TODO) with edits. Never open findings.json or a full output whole: grep it for the one "
                 "address or code you need.")
    return "\n".join(lines) + "\n"


def cell(text):
    return " ".join(str(text).split()).replace("|", "/")


def draft(r, svc_adv):
    fs = r["findings"]
    rows_by = {k: sum(1 for code, fl in groups(fs) if fl[0]["priority"] == k and code != "CLIENT-UPDATE") for k in ORDER}
    icon = {"Possible compromise": "🔴", "Attempted attack": "🟠", "No sign of attack": "🟢"}.get(r["verdict"], "⚪")
    d = ["# FileMaker Server security check", "",
         "> **Private.** This report names accounts, addresses and weaknesses. Don't publish or forward it.", ">",
         "> **Limits.** This report comes from one skill, cadenceux-fms-security: a set of automated checks,",
         "> offered as is, with no guarantee or support. It doesn't replace a security assessment by", "> professionals.", "",
         "| | |", "|---|---|",
         f"| **Server** | {r['host']}. TODO: where it runs |",
         f"| **Checked** | {r['checked'][:10]}. TODO: from where the exposure check ran |",
         f"| **Result** | {icon} {r['verdict']}. TODO: confirm once the addresses are confirmed |",
         "| **To fix** | " + " · ".join(f"{rows_by[k]} {k}" for k in ("Critical", "High", "Medium", "Low")) + " |", "",
         "## What to fix", "",
         "| # | Priority | What we found | Why it matters | What to do | Owner | Status |",
         "|---|---|---|---|---|---|---|"]
    rows = [(code, fl) for code, fl in groups(fs) if code != "CLIENT-UPDATE"]
    for i, (code, fl) in enumerate(rows, 1):
        f = fl[0]
        found = f["title"] + (f" ({len(fl)})" if len(fl) > 1 else "") + ": " + "; ".join(
            short((x["address"] + " " if x["address"] else "") + x["detail"], 110) for x in fl[:3]) + (
            f"; and {len(fl) - 3} more" if len(fl) > 3 else "")
        d.append(f"| {i} | {EMOJI.get(f['priority'], f['priority'])} | {cell(found)} | {cell(f['why'])} | {cell(f['todo'])} | TODO | Open |")
    if not rows:
        d.append("| | | Nothing to fix from the automated checks | | | | |")
    d += ["", "## Recovery readiness", "",
          "| | The owner expects | Today | Gap | What to do | Owner |", "|---|---|---|---|---|---|",
          "| **Data loss** | TODO (intake) | TODO | | | |", "| **Down time** | TODO (intake) | TODO | | | |",
          "| **Clean copy** | One copy beyond the server's network | TODO | | | |",
          "| **Last password reset** | TODO | TODO | | | |", "| **DR plan** | Written and agreed with the owner | TODO | | | |", "",
          "Every gap here is also a row in \"What to fix\", with its priority, owner and status.", "",
          "## What passed", "", "| Check | Result |", "|---|---|"]
    codes = {f["code"] for f in fs}
    ran = r["ran"]
    passed = []
    if "exposure" in ran and ran["exposure"]["exit"] == 0:
        closed = sum(1 for p in r["ports"] if p["state"] != "OPEN")
        passed += [("Ports", f"✅ {closed} of {len(r['ports'])} ports closed or filtered")] if not codes & {"PORT-OPEN"} else []
        for code, label, text in (("FILE-LIST-OPEN", "File list", "Hosted file names aren't listed without sign-in"),
                                  ("CERTIFICATE", "Certificate", "The certificate is trusted"),
                                  ("TLS-OLD", "Old TLS", "TLS 1.0 and 1.1 are refused"), ("HSTS-OFF", "HSTS", "HSTS is on"),
                                  ("HTTP-NO-REDIRECT", "Port 80", "Port 80 redirects to HTTPS"),
                                  ("PHP-ON", "PHP", "PHP doesn't answer from outside"), ("XML-ON", "XML", "XML publishing is off")):
            if code not in codes:
                passed.append((label, "✅ " + text))
        if "services" in ran and not any(c.startswith("SERVICE-CVE") for c in codes) and svc_adv.get("services"):
            passed.append(("Services", "✅ No published issues for the versions the open services show"))
        if r["os_support"].get("state") == "supported":
            passed.append(("Operating system", "✅ " + r["os_support"]["text"]))
    if r["logs_files"]:
        for code, text in (("POSSIBLE-COMPROMISE", "No address failed and then signed in the way attacks do"),
                           ("XDBC", "No failed sign-ins through ODBC/JDBC (2399)"),
                           ("HIGH-VOLUME", "No bulk record downloads"), ("ADMIN-NEW", "No Admin Console sign-in from a new address")):
            if code not in codes:
                passed.append(("Logs", "✅ " + text))
    if r["advisories"].get("version") and not r["advisories"].get("issues"):
        passed.append(("Published issues", f"✅ None affect FileMaker Server {r['advisories']['version']}"))
    d += [f"| {a} | {cell(b)} |" for a, b in passed] or ["| | TODO |"]
    d += ["", "## Staff computers to update", ""]
    clients = [f for f in fs if f["code"] == "CLIENT-UPDATE"]
    if clients:
        d += ["| FileMaker Pro version | Machines | Issue | Update to |", "|---|---|---|---|"]
        d += [f"| {cell(short(f['detail'], 60))} | TODO | {cell(f['title'])} | TODO |" for f in clients]
    else:
        d.append("None: no client version with a published issue connected." if r["logs_files"] else "Not checked: no logs read.")
    not_checked = [("Server settings", "Needs the Admin Console sign-in", "Run fms_admin_review.py in your own terminal"),
                   ("Hosted file security", "Needs Save a Copy as XML exports", "Export each file, then run fms_file_audit.py"),
                   ("Backups and restores", "Can't be seen from outside", "TODO: from the owner and the Admin Console"),
                   ("Patch level, kernel, UDP services", "Not visible from outside, to anyone", "Keep the server's own updates on")]
    if not r["logs_files"]:
        not_checked.insert(0, ("Logs", "None were supplied", "Share the Logs folder as a zip and run the check again"))
    if not r["fms_version"]:
        not_checked.insert(0, ("Published issues for FileMaker Server", "The version wasn't known",
                               "Give the version from the Admin Console"))
    d += ["", "## Not checked", "", "| What | Why | How to cover it |", "|---|---|---|"]
    d += [f"| {a} | {b} | {c} |" for a, b, c in not_checked]
    d += ["", "## Next steps", "", "1. TODO: the one or two fixes that matter most",
          "2. TODO: where no DR plan is agreed, agree how much data the owner can lose and how long they can be down",
          "3. Re-run the check after fixing, to confirm.", "4. TODO: log check schedule (references/log-review.md)", "",
          "## For your FileMaker administrator", "",
          f"- Checked {r['checked']} with `fms_scan.py {r['host']}`"
          + (f" (intended: {', '.join(r['intended'])})" if r["intended"] else " (no intended services given)") + ".",
          f"- Logs: {', '.join(r['logs_files'])}, from {r['since']}." if r["logs_files"] else "- Logs: not read.",
          "- Published issues: " + (r["advisories"].get("source") or "not looked up") + ".",
          "- Full output of each check is in the scan folder: exposure.txt, service-advisories.txt, advisories.txt, logcheck.txt."]
    if r["warnings"]:
        d += ["- Warnings: " + "; ".join(cell(w) for w in r["warnings"])]
    return "\n".join(d) + "\n"


if __name__ == "__main__":
    main()
