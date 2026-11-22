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
    # A quiet night (one failure an hour), then an hour where 12 rotating addresses each try once
    for h in range(1, 10):
        f.write(f'2026-11-03 0{h}:05:00.000 +1100\tWarning\t661\tsrv\tSECURITY: Client "s [10.0.0.9]" '
                f'authentication failed on database "Sales" using "staff{h} [fmapp]"\n')
    for i in range(12):
        f.write(f'2026-11-03 12:{i:02d}:00.000 +1100\tWarning\t661\tsrv\tSECURITY: Client "r [192.0.2.{i + 10}]" '
                f'authentication failed on database "Sales" using "api{i % 7} [fmrest]"\n')

# The log check: --brief is shorter, and --save writes exactly the full output
full = run(os.path.join(HERE, "fms_logcheck.py"), LOGS, "2020-01-01 00:00").stdout
saved = os.path.join(ROOT, "saved.txt")
brief = run(os.path.join(HERE, "fms_logcheck.py"), LOGS, "2020-01-01 00:00", "--brief", "--save", saved).stdout
check("log check: --save writes the full output, unchanged", open(saved).read() == full)
check("log check: --brief is shorter and says what it left out", len(brief) < len(full) and "more addresses" in brief)
check("log check: --brief keeps the address that sprayed", "198.51.100.7" in brief.split("## Failed")[1])
wide = full.split("## Server-wide failed sign-ins")[1].split("\n## ")[0]
check("log check: the rotating-address hour is a server-wide SPIKE, marked SPREAD",
      "2026-11-03 12:00" in wide and "SPREAD" in wide.split("2026-11-03 12:00")[1].splitlines()[0])
check("log check: a quiet hour is not a spike, and the median is the quiet rate", "2026-11-03 05:00" not in wide
      and "median 1 an hour" in full)
check("log check: the file every address tried is FILE-TARGETED", "Sales" in wide and "FILE-TARGETED" in wide)

# The Data API and OData logs (OttoFMS downloads these, not the web server's log): the Claris pattern of a file list,
# then the layouts, then page after page from each; addresses that list the files and try sign-ins; a sync
# integration paging one layout; Guest through OData; and a generic account name. Access.log has a Guest WebDirect sign-in.
API_LOGS = os.path.join(ROOT, "ApiLogs")
os.makedirs(API_LOGS)
with open(os.path.join(API_LOGS, "Access.log"), "w") as f:
    f.write('2026-11-01 09:00:00.000 +1100\tInformation\t638\tsrv\tClient "staff (PC1 [10.0.0.1])" opening a connection '
            'from "PC1 (203.0.113.1)" using "FileMaker Pro 26.0.3 [fmapp]".\n')
    f.write('2026-11-03 09:00:00.000 +1100\tInformation\t638\tsrv\tClient "[WebDirect-AB12C] (WD-AB12C) [198.51.100.40]" '
            'opening a connection from "WD-AB12C (198.51.100.40)" using "Server [fmwebdirect]".\n')
    f.write('2026-11-03 09:00:01.000 +1100\tInformation\t94\tsrv\tClient "[WebDirect-AB12C] (WD-AB12C) [198.51.100.40]" '
            'opening database "Sales" as "[Guest]".\n')
with open(os.path.join(API_LOGS, "Event.log"), "w") as f:
    f.write('2026-11-01 09:00:00.000 +1100\tInformation\t30\tsrv\tServer started\n')
D = "2026-11-03 10:{:02d}:{:02d}.000 +1100\t{}\tINFO\t{}\t{}\t{}\t{}\t100\n"
with open(os.path.join(API_LOGS, "fmdapi.log"), "w") as f:
    f.write("Timestamp\tError\tLevel\tIP_Address\tUser\tHTTP\tMessage\tUsage\n")
    f.write(D.format(0, 0, 0, "198.51.100.66", "", "GET", "/fmi/data/vLatest/databases"))
    f.write(D.format(0, 5, 0, "198.51.100.66", "sales", "GET", "/fmi/data/vLatest/databases/Sales/layouts"))
    for i in range(6):
        for page in range(5):
            f.write(D.format(1 + i, page, 0, "198.51.100.66", "sales", "GET",
                             f"/fmi/data/vLatest/databases/Sales/layouts/L{i}/records?_offset={1 + 200 * page}&_limit=200"))
    for i in range(25):
        f.write(D.format(20, i, 0, "203.0.113.9", "sync", "GET",
                         f"/fmi/data/v2/databases/Sales/layouts/Invoices/records?_offset={1 + 100 * i}&_limit=100"))
    for i in range(8):
        f.write(D.format(30 + i, 0, 0, f"192.0.2.{50 + i}", "", "GET", "/fmi/data/v1/databases"))
        f.write(D.format(30 + i, 5, 212, f"192.0.2.{50 + i}", "", "POST", "/fmi/data/v1/databases/Sales/sessions"))
    f.write(D.format(40, 0, 0, "203.0.113.20", "api", "GET", "/fmi/data/v1/databases/Sales/layouts/Web/records"))
    f.write(D.format(41, 0, 0, "203.0.113.20", "api", "GET", "/fmi/data/v1/databases/Sales/layouts/Web/records"))
with open(os.path.join(API_LOGS, "fmodata.log"), "w") as f:
    f.write("Timestamp\tError\tLevel\tIP_Address\tUser\tHTTP\tMessage\tUsage\tInfo\n")
    f.write("2026-11-02T23:50:00.000000Z\t0\tINFO\t198.51.100.77\t[Guest]\tGET\t/fmi/odata/v4/Sales/Contacts?$skip=0\t50\t\n")
    f.write("2026-10-01T23:50:00.000000Z\t0\tINFO\t198.51.100.88\tsales\tGET\t/fmi/odata/v4/Sales/Contacts\t50\t\n")
api = run(os.path.join(HERE, "fms_logcheck.py"), API_LOGS, "2026-11-01 00:00").stdout
sect = api.split("## Data API and OData requests")[1].split("\n## ")[0]
row = lambda ip: next((l for l in sect.splitlines() if l.startswith("  " + ip + " ")), "")
check("api logs: the file list, layouts, then pages from 6 layouts is MAPPED, BURST and PAGING",
      all(x in row("198.51.100.66") for x in ("MAPPED", "BURST", "PAGING", "layouts=6", "records=30")))
check("api logs: a sync paging one layout 25 times is PAGING, not MAPPED", "PAGING" in row("203.0.113.9")
      and "MAPPED" not in row("203.0.113.9"))
check("api logs: the addresses that only listed files are one line, with the failed sign-ins counted",
      "FILE-LIST 8 addresses" in sect and "8 then failed to sign in" in sect and not row("192.0.2.50"))
check("api logs: Guest through OData is GUEST, with OData's UTC time read as the server's", "GUEST" in row("198.51.100.77")
      and "2026-11-03 10:50" in row("198.51.100.77"))
check("api logs: a generic account name is flagged", "GENERIC/DEFAULT" in row("203.0.113.20"))
check("api logs: a call before the window isn't counted", not row("198.51.100.88") and "fmodata.log" in sect.splitlines()[0])
guest = api.split("## Guest sign-ins")[1].split("\n## ")[0]
check("guest: the WebDirect Guest sign-in is listed with its file", "198.51.100.40" in guest and "Sales" in guest
      and "WEBDIRECT" in guest)
import fms_findings  # noqa: E402
warn = []
found = {(f["code"], f["address"]) for f in fms_findings.parse_logcheck(api, warn)}
check("api findings: each flag becomes its finding, with no warnings",
      {("API-MAPPED", "198.51.100.66"), ("API-PAGING", "203.0.113.9"), ("GUEST-SIGNIN", "198.51.100.77"),
       ("GUEST-SIGNIN", "198.51.100.40"), ("API-GENERIC", "203.0.113.20"), ("API-FILE-LIST", "")} <= found and not warn)
wording = {t["code"] for t in json.load(open(os.path.join(HERE, "..", "references", "finding-templates.json")))}
check("api findings: every new code has its wording", {c for c, _ in found} <= wording)

# The attack pattern in Claris's lockdown guide, as one address's Event.log lines: a list of account names (admin and
# its kind, plus a random one), each tried twice about 0.6 seconds apart, file after file. It must be caught the same
# whichever door it comes through, and an address that tries several doors is flagged for that too. Each door's
# address is in its own folder, so each is judged alone.
NAMES = ["q8r3tz", "admin", "website", "fmsadmin", "boomer", "fmserver"]
DOOR_IPS = {"fmapp": "198.51.100.11", "fmwebdirect": "198.51.100.12", "fmrest": "198.51.100.13",
            "fmodata": "198.51.100.14", "fmxdbc": "198.51.100.15", "admin-console": "198.51.100.16"}


def attack_line(n, ip, door, start=960):
    acct, t = NAMES[(n // 2) % 6], start + n * 0.6
    when = f"2026-03-14 02:{int(t // 60):02d}:{t % 60:06.3f} -0700"
    if door == "admin-console":
        return f'{when}\tWarning\t522\tsrv\tSECURITY: Administrator authentication failed: "{acct} [{ip}]" (admin console).\n'
    return (f'{when}\tWarning\t661\tsrv\tSECURITY: Client "{acct} [{ip}]" authentication failed on database '
            f'"File{(n // 12) % 9}.fmp12" using "{acct} [{door}]".\n')


def attack_folder(name, events, access=()):
    folder = os.path.join(ROOT, name)
    os.makedirs(folder)
    with open(os.path.join(folder, "Access.log"), "w") as f:
        f.write('2026-03-14 01:00:00.000 -0700\tInformation\t638\tsrv\tClient "staff (PC1 [10.0.0.1])" opening a connection '
                'from "PC1 (203.0.113.1)" using "FileMaker Pro 26.0.3 [fmapp]".\n')
        f.writelines(access)
    with open(os.path.join(folder, "Event.log"), "w") as f:
        f.write('2026-03-14 02:16:00.294 -0700\tInformation\t150\tsrv\tSchedule "Nightly cleanup" completed.\n')
        f.writelines(events)
    return run(os.path.join(HERE, "fms_logcheck.py"), folder, "2026-03-14 00:00").stdout


def failed_row(text, ip):
    return next((l for l in text.split("## Failed FileMaker sign-ins")[1].splitlines() if l.startswith("  " + ip)), "")


for door, ip in DOOR_IPS.items():
    text = attack_folder("Attack-" + door, [attack_line(n, ip, door) for n in range(248)])
    row = failed_row(text, ip)
    want = ["n=248", "accts=6", "NEVER-SUCCEEDED", "MANY-ACCOUNTS", "GENERIC/DEFAULT", "RATE"] \
        + (["MANY-FILES"] if door != "admin-console" else []) + (["XDBC"] if door == "fmxdbc" else [])
    check(f"attack pattern through {door}: caught with the same flags", all(x in row for x in want) or print(row))
    check(f"attack pattern through {door}: a server-wide spike", "SPIKE" in text.split("## Server-wide")[1].split("\n## ")[0])
    found = [f["code"] for f in fms_findings.parse_logcheck(text, []) if f["address"] == ip]
    check(f"attack pattern through {door}: one finding, the most serious flag",
          found[:1] == (["XDBC"] if door == "fmxdbc" else ["RATE"]))

# One address, every door in turn, a few tries each: too slow for RATE, still caught for the doors and the names
mixed = attack_folder("Attack-doors", [attack_line(n, "198.51.100.20", door, start=960 + 90 * i)
                                       for i, door in enumerate(DOOR_IPS) for n in range(2 * i, 2 * i + 3)])
row = failed_row(mixed, "198.51.100.20")
check("attack pattern through every door: MANY-DOORS, MANY-ACCOUNTS and GENERIC/DEFAULT, without RATE",
      all(x in row for x in ("MANY-DOORS", "MANY-ACCOUNTS", "GENERIC/DEFAULT", "admin-console")) and "RATE" not in row
      or print(row))
# Signed in first, then the spray: a sign-in counts whether it came before or after the failures
ip = "198.51.100.31"
first = attack_folder("Attack-signed-in-first", [attack_line(n, ip, "fmxdbc") for n in range(60)], [
    f'2026-03-14 01:55:16.112 -0700\tInformation\t638\tsrv\tClient "admin" opening a connection from "{ip} ({ip})" using "JDBC [fmxdbc]".\n',
    f'2026-03-14 01:55:16.112 -0700\tInformation\t94\tsrv\tClient "admin ({ip}) [{ip}]" opening database "File0" as "admin".\n'])
row = failed_row(first, ip)
check("signed in before the failures: POSSIBLE-COMPROMISE and SIGNED-IN with the account, time and connection",
      all(x in row for x in ("POSSIBLE-COMPROMISE", "SIGNED-IN as admin 2026-03-14 01:55 via JDBC")) or print(row))
check("signed in before the failures: one Critical finding for it",
      [f["code"] for f in fms_findings.parse_logcheck(first, []) if f["address"] == ip][:1] == ["POSSIBLE-COMPROMISE"])
# File after file, slowly, with names nobody uses: no RATE, no admin names, still caught for the files
slow = attack_folder("Attack-slow-files", [
    f'2026-03-14 03:{3 * n:02d}:07.000 -0700\tWarning\t661\tsrv\tSECURITY: Client "{u} [198.51.100.32]" authentication '
    f'failed on database "File{n}.fmp12" using "{u} [fmapp]".\n' for n, u in enumerate(["jsmith", "mjones"] * 6)])
row = failed_row(slow, "198.51.100.32")
check("one address, file after file, slowly, ordinary names: MANY-FILES without RATE",
      "MANY-FILES" in row and "files=12" in row and "RATE" not in row or print(row))
check("one address, file after file: a High finding",
      [f["code"] for f in fms_findings.parse_logcheck(slow, []) if f["address"] == "198.51.100.32"][:1] == ["MANY-FILES"])
check("attack pattern: the names attackers try on our servers are generic, fmadmin included",
      {"fmadmin", "administrator", "root", "test", "guest"} <= __import__("fms_logcheck").GENERIC)

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
check("scan: the spike and the targeted file are findings", {"SPIKE", "FILE-TARGETED"} <= {f["code"] for f in r["findings"]})
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

# The file audit on a small made-up export: [Full Access] with more than fmapp, no fmplugin, an old minimum version
import fms_file_audit  # noqa: E402
SAXML = os.path.join(ROOT, "Sales.xml")
with open(SAXML, "w") as f:
    f.write('<?xml version="1.0"?><FMSaveAsXML version="2.3.0.1" File="Sales.fmp12"><Structure><AddAction>'
            '<Options><OnOpen><Minimum version="12.0" value="1208"></Minimum><Login type="-1"></Login></OnOpen></Options>'
            '<AccountsCatalog><Account enable="True" type="FileMaker"><Authentication><AccountName>dev</AccountName>'
            '</Authentication><PrivilegeSetReference name="[Full Access]"/></Account>'
            '<Account enable="True" type="FileMaker"><Authentication><AccountName>clerk</AccountName></Authentication>'
            '<PrivilegeSetReference name="Clerk"/></Account></AccountsCatalog>'
            '<PrivilegeSetsCatalog><PrivilegeSet name="Clerk"><access><Other Print="True" Export="True"/></access></PrivilegeSet>'
            '</PrivilegeSetsCatalog><ExtendedPrivilegesCatalog>'
            '<ExtendedPrivilege name="fmapp"><PrivilegeSetReference name="[Full Access]"/><PrivilegeSetReference name="Clerk"/></ExtendedPrivilege>'
            '<ExtendedPrivilege name="fmwebdirect"><PrivilegeSetReference name="[Full Access]"/></ExtendedPrivilege>'
            '<ExtendedPrivilege name="fmreauthenticate10"><PrivilegeSetReference name="[Full Access]"/></ExtendedPrivilege>'
            '</ExtendedPrivilegesCatalog></AddAction></Structure></FMSaveAsXML>')
_, fa = fms_file_audit.audit(SAXML)
codes = {c: t for _, c, t in fa}
check("file audit: [Full Access] with fmwebdirect is flagged, fmreauthenticate10 isn't", "fmwebdirect" in codes.get("F6", "")
      and "fmreauthenticate10 (" not in codes.get("F6", "").split("should")[0])
check("file audit: a set without fmreauthenticate, export rights, no fmplugin and minimum 12.0 are each reported",
      "Clerk" in codes.get("F13", "") and "Clerk" in codes.get("F14", "") and "F15" in codes and "12.0" in codes.get("F16", ""))

# The admin review against made-up Admin API answers: plug-ins per engine, idle timeout, Remote Backup, Secure folder
import contextlib  # noqa: E402
import io  # noqa: E402
import fms_admin_review  # noqa: E402
ANSWERS = {
    "/plugins": {"plugins": [{"pluginName": "BaseElements", "enabled": True}]},
    "/plugins/DbsPluginConfig": {"config": {"usePlugins": True, "allowInstallPlugin": True}},
    "/plugins/WpePluginConfig": {"config": {"iwpEnablePlugins": False, "iwpAllowInstallPlugins": False}},
    "/plugins/DAPIPluginConfig": {"config": {"DAPIEnablePlugins": False, "DAPIAllowInstallPlugins": False}},
    "/fmclients/sessiontimeout/progo": {"enableProGoTimeout": False, "sessionTimeout": 30},
    "/remotebackup/drives": {"drives": []},
    "/databases": {"databases": [{"filename": "B.fmp12", "folder": "filemac:/HD/FMS/Data/Databases/", "isEncrypted": True}]},
    "/server/currentfoldersettings": {"secureDatabaseFolder": "filemac:/HD/FMS/Data/Secure/"},
}


class FakeApi:
    def get(self, path):
        return ANSWERS.get(path)


with contextlib.redirect_stdout(io.StringIO()) as said:
    fms_admin_review.review(FakeApi())
said = said.getvalue()
check("admin review: an operating-system plug-in, the Script Engine's plug-ins and allow-install are each raised",
      "BaseElements can run operating-system commands" in said and "plug-ins on for: Script Engine" in said
      and "install plug-ins" in said)
check("admin review: no Pro/Go idle timeout, no Remote Backup drive, and a file outside the Secure folder are raised",
      "never time out" in said and "no Remote Backup drive" in said and "ready to move: B.fmp12" in said)
import fms_findings  # noqa: E402
waf = fms_findings.parse_exposure("## Front door (443): Cloudflare (CF-RAY); the server's own address 192.0.2.5 "
                                  "answers on 443  <-- WAF-BYPASS: block direct connections to it")
check("exposure: a server answering around its WAF is a WAF-BYPASS finding", [f["code"] for f in waf] == ["WAF-BYPASS"])

# The shared templates cover every code the findings module can raise
tpl = {t["code"] for t in json.load(open(os.path.join(HERE, "..", "references", "finding-templates.json")))}
src = open(os.path.join(HERE, "fms_findings.py")).read() + open(os.path.join(HERE, "fms_scan.py")).read()
import re  # noqa: E402
raised = set(re.findall(r'"([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)"', src)) - {"NEVER-SUCCEEDED", "BEFORE-ACCESS-LOG", "GUEST-GENERIC", "FILE-LIST"}
raised = {c for c in raised if not c.startswith(("FMS-", "UTF-"))}
check("templates: every code the findings can raise has wording", not (raised - tpl - {"SETTING-FAIL", "SETTING-REVIEW"}) or print(sorted(raised - tpl)))

print(f"\n{sum(results)} of {len(results)} passed")
sys.exit(0 if all(results) else 1)
