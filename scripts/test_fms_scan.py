#!/usr/bin/env python3
"""Tests for fms_scan.py and fms_logcheck.py --brief: made-up log lines, no network.

Run: python3 test_fms_scan.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fms_scan  # noqa: E402

results = []


def check(name, ok):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name)


def run(*args):
    return subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)


# A Logs folder: 40 addresses that connected, and one that sprayed generic account names
ROOT = tempfile.mkdtemp(prefix="fms_scan_test_")
LOGS = os.path.join(ROOT, "Logs")
os.makedirs(LOGS)
with open(os.path.join(LOGS, "Access.log"), "w") as f:
    for i in range(40):
        f.write(f'2026-11-03 10:{i:02d}:00.000 +1100\tInformation\t638\tsrv\tClient "u{i} (PC{i} [10.0.0.{i}])" opening a '
                f'connection from "PC{i} (203.0.113.{i})" using "FileMaker Pro 26.0.3 [fmapp]".\n')
    f.write('2026-11-03 11:30:00.000 +1100\tInformation\t638\tsrv\tClient "admin (X [198.51.100.7])" opening a connection '
            'from "X (198.51.100.7)" using "FileMaker Pro 26.0.3 [fmapp]".\n')
with open(os.path.join(LOGS, "Event.log"), "w") as f:
    for i, acct in enumerate(["admin", "Admin", "web", "guest", "test"] * 5):
        f.write(f'2026-11-03 11:{i:02d}:00.000 +1100\tWarning\t661\tsrv\tSECURITY: Client "x [198.51.100.7]" '
                f'authentication failed on database "Sales" using "{acct} [fmapp]"\n')

# The log check: --brief is shorter, and --save writes exactly the full output
full = run(os.path.join(HERE, "fms_logcheck.py"), LOGS, "2020-01-01 00:00").stdout
saved = os.path.join(ROOT, "saved.txt")
brief = run(os.path.join(HERE, "fms_logcheck.py"), LOGS, "2020-01-01 00:00", "--brief", "--save", saved).stdout
check("log check: --save writes the full output, unchanged", open(saved).read() == full)
check("log check: --brief is shorter and says what it left out", len(brief) < len(full) and "more addresses" in brief)
check("log check: --brief keeps the address that sprayed", "198.51.100.7" in brief.split("## Failed")[1])

# The whole scan, offline, logs only
out = os.path.join(ROOT, "scan")
done = run(os.path.join(HERE, "fms_scan.py"), "srv.example", "--no-exposure", "--offline", "--logs", LOGS,
           "--intended", "FileMaker Pro and Go", "--out", out)
check("scan: runs and prints a summary", done.returncode == 0 and done.stdout.startswith("##### FMS scan: srv.example"))
check("scan: the summary is small", len(done.stdout) < 6000)
check("scan: saves the full outputs, findings, draft and summary",
      all(os.path.exists(os.path.join(out, n)) for n in ("logcheck.txt", "logcheck-brief.txt", "findings.json",
                                                         "report-draft.md", "summary.txt")))
r = json.load(open(os.path.join(out, "findings.json")))
check("scan: the spraying address is a finding with its template's wording",
      any(f["address"] == "198.51.100.7" and f["code"] == "MANY-ACCOUNTS" for f in r["findings"])
      and r["wording"]["MANY-ACCOUNTS"]["title"] and r["wording"]["MANY-ACCOUNTS"]["todo"])
check("scan: findings.json has one finding per line, for grep",
      sum(1 for line in open(os.path.join(out, "findings.json")) if line.startswith('{"priority"')) == len(r["findings"]))
check("scan: spraying that never signed in is an attempted attack", r["verdict"] == "Attempted attack")
check("scan: the summary lists the address to confirm", "Addresses to confirm" in done.stdout and "198.51.100.7" in done.stdout)
draft = open(os.path.join(out, "report-draft.md")).read()
check("scan: the draft has the report's sections, with TODOs for what only the user knows",
      all(h in draft for h in ("## What to fix", "## Recovery readiness", "## What passed", "## Not checked",
                               "## For your FileMaker administrator")) and "TODO (intake)" in draft)
check("scan: without an exposure check, ports aren't claimed as passed", "ports closed" not in draft)

# Intended services and the web ports
il = fms_scan.intended_list
check("intended: names matched loosely", il("filemaker pro, WebDirect, odbc") == ["FileMaker Pro and Go", "WebDirect", "ODBC/JDBC"])
F = fms_scan.finding
found = [F("exposure", "SERVICE-ON", "Data API answers", flags="Data API"), F("exposure", "SERVICE-ON", "WebDirect answers", flags="WebDirect")]
ports = [{"port": 443, "state": "OPEN"}, {"port": 5003, "state": "OPEN"}]
kept, accepted = fms_scan.judge_intended(found, ports, ["WebDirect"])
check("intended: an intended service is accepted, the other still raised, and 5003 questioned",
      accepted == ["WebDirect"] and [f["flags"] for f in kept if f["code"] == "SERVICE-ON"] == ["Data API"]
      and any(f["code"] == "PORT-NOT-INTENDED" and "5003" in f["detail"] for f in kept))
kept, _ = fms_scan.judge_intended([], ports, ["FileMaker Pro and Go", "WebDirect"])
check("intended: nothing questioned when both ports are needed", kept == [])

# The shared templates cover every code the findings module can raise
tpl = {t["code"] for t in json.load(open(os.path.join(HERE, "..", "references", "finding-templates.json")))}
src = open(os.path.join(HERE, "fms_findings.py")).read() + open(os.path.join(HERE, "fms_scan.py")).read()
import re  # noqa: E402
raised = set(re.findall(r'"([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)"', src)) - {"NEVER-SUCCEEDED", "BEFORE-ACCESS-LOG", "GUEST-GENERIC"}
raised = {c for c in raised if not c.startswith(("FMS-", "UTF-"))}
check("templates: every code the findings can raise has wording", not (raised - tpl - {"SETTING-FAIL", "SETTING-REVIEW"}) or print(sorted(raised - tpl)))

print(f"\n{sum(results)} of {len(results)} passed")
sys.exit(0 if all(results) else 1)
