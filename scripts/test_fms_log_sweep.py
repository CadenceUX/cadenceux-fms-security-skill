#!/usr/bin/env python3
"""Tests for fms_log_sweep.py: made-up download folders for three servers, no network.

Run: python3 test_fms_log_sweep.py
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fms_log_sweep as S  # noqa: E402

results = []


def check(name, ok):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name)


ROOT = tempfile.mkdtemp(prefix="fms_sweep_test_")
SERVERS = {"one.example.com": "+1100", "two.example.com": "+1100", "three.example.com": "-0700"}


def stamp(host, minute, second=0, hour=10, day=20):
    """The same moment on each server, written in that server's own time zone."""
    shift = {"+1100": 0, "-0700": -18}[SERVERS[host]]
    h = hour + shift
    d = day + (h // 24)
    return f"2026-11-{d:02d} {h % 24:02d}:{minute:02d}:{second:02d}.000 {SERVERS[host]}"


def fail(host, ip, acct, file="Sales.fmp12", door="fmrest", minute=0, second=0, hour=10, day=20, client=None):
    c = client if client is not None else acct
    return (f'{stamp(host, minute, second, hour, day)}\tWarning\t661\t{host}\tSECURITY: Client "{c} [{ip}]" authentication '
            f'failed on database "{file}" using "{acct} [{door}]".\n')


def opened(host, ip, acct, file="Sales", minute=30, hour=10, day=20, client="x (PC)"):
    return (f'{stamp(host, minute, 0, hour, day)}\tInformation\t94\t{host}\tClient "{client} [{ip}]" opening database '
            f'"{file}" as "{acct}".\n')


events = {h: [] for h in SERVERS}
access = {h: [] for h in SERVERS}
# A sustained attack across two servers: admin-type names and a breach list of email addresses, never signing in
for i in range(150):
    host = "one.example.com" if i % 2 else "two.example.com"
    name = ["admin", "fmadmin", "fmsadmin", f"user{i}@gmail.com", f"x{i}@orange.fr"][i % 5]
    events[host].append(fail(host, "198.51.100.1", name, f"File{i % 4}.fmp12", minute=i % 60, second=i % 60, hour=3))
# A campaign: 12 addresses, two tries each, in the same hour on all three servers, names from a tool's list and the file
for i in range(12):
    host = list(SERVERS)[i % 3]
    events[host].append(fail(host, f"192.0.2.{i + 10}", "daapi", minute=i))
    events[host].append(fail(host, f"192.0.2.{i + 10}", "Sales", minute=i, second=5))
# Staff: one mistyped password, then signed in
events["one.example.com"].append(fail("one.example.com", "203.0.113.5", "jane", client="jane (Jane's Mac)", door="fmapp"))
access["one.example.com"].append(opened("one.example.com", "203.0.113.5", "jane", client="jane (Jane's Mac)"))
# A school's network: 30 staff names, two Admin tries, and sign-ins
for i in range(30):
    events["two.example.com"].append(fail("two.example.com", "203.0.113.6", f"teacher{i}", door="fmapp", minute=i))
events["two.example.com"] += [fail("two.example.com", "203.0.113.6", "Admin", door="fmapp", minute=40)] * 2
access["two.example.com"].append(opened("two.example.com", "203.0.113.6", "teacher1"))
# An attack that got in: many admin-type names, then a sign-in as admin
for i, name in enumerate(["admin", "fmadmin", "fmsadmin", "test", "guest", "administrator"] * 2):
    events["three.example.com"].append(fail("three.example.com", "198.51.100.9", name, minute=i, hour=5))
access["three.example.com"].append(opened("three.example.com", "198.51.100.9", "admin", hour=6))
# The attacker that got in also fails on admin several times before signing in as admin: a run, rated High
events["three.example.com"] += [fail("three.example.com", "198.51.100.9", "admin", minute=20 + i, hour=5) for i in range(4)]
# Staff: three separate wrong passwords, then in. One wrong password in a multi-file solution fails once per file
events["one.example.com"] += [fail("one.example.com", "203.0.113.30", "mia", door="fmapp", minute=m, hour=8) for m in (0, 5, 9)]
access["one.example.com"].append(opened("one.example.com", "203.0.113.30", "mia", minute=12, hour=8))
events["one.example.com"] += [fail("one.example.com", "203.0.113.31", "mark", f"F{i}.fmp12", door="fmapp", minute=0, hour=9) for i in range(5)]
access["one.example.com"].append(opened("one.example.com", "203.0.113.31", "mark", minute=1, hour=9))
# Guessing one person's password: 12 attempts in half an hour, then in
events["two.example.com"] += [fail("two.example.com", "192.0.2.200", "cfo", minute=2 * i, hour=7) for i in range(12)]
access["two.example.com"].append(opened("two.example.com", "192.0.2.200", "cfo", minute=40, hour=7))
# Verified: by address, and by computer
for i in range(30):
    events["one.example.com"].append(fail("one.example.com", "203.0.113.7", "admin", minute=i, hour=2))
    events["one.example.com"].append(fail("one.example.com", "203.0.113.8", "admin", minute=i, hour=2,
                                          client="admin (Office iMac)", door="fmapp"))
# The server itself and a private address are never attackers
events["two.example.com"] += [fail("two.example.com", "127.0.0.1", "admin", minute=m) for m in range(30)]
events["two.example.com"] += [fail("two.example.com", "10.0.0.4", "admin", minute=m) for m in range(30)]
# Guest through WebDirect
access["three.example.com"].append(opened("three.example.com", "198.51.100.40", "[Guest]", client="[WebDirect-AB12C] (WD-AB12C)"))
# Signed in as admin first, then failed on six names, three of them not admin-type
access["three.example.com"].append(opened("three.example.com", "198.51.100.80", "admin", minute=45, hour=6))
events["three.example.com"] += [fail("three.example.com", "198.51.100.80",
                                     ["q8r3tz", "admin", "website", "fmsadmin", "boomer", "fmserver"][i % 6],
                                     f"Orders{i % 2}.fmp12", door="fmxdbc", minute=10 + i, hour=7) for i in range(15)]
# File after file with ordinary names, slowly, never signing in: the multi-file pattern, without admin names
events["three.example.com"] += [fail("three.example.com", "198.51.100.60", ["jsmith", "mjones"][i % 2], f"Shop{i}.fmp12",
                                     door="fmapp", minute=3 * i, hour=1) for i in range(12)]
# An old iPad with a saved password: a real person's name, retried on four files, while its owner signs in from the office
events["two.example.com"] += [fail("two.example.com", "203.0.113.41", "olivia", f"Stock{i}.fmp12", door="fmapp",
                                   minute=10 * i, hour=4) for i in range(4)]
access["two.example.com"].append(opened("two.example.com", "203.0.113.40", "olivia", minute=5, hour=4))
# One wrong password on an eight-file solution, never retried: one attempt, not file after file
events["two.example.com"] += [fail("two.example.com", "203.0.113.42", "tom", f"Part{i}.fmp12", door="fmapp",
                                   minute=30, second=i, hour=4) for i in range(8)]

for host in SERVERS:
    folder = os.path.join(ROOT, f"{host}-2026-11-21-090000")
    os.makedirs(folder)
    with open(os.path.join(folder, "Event.log"), "w") as f:
        f.writelines(events[host])
    with open(os.path.join(folder, "Access.log"), "w") as f:
        f.writelines(access[host])
# An older download of one server, which the sweep skips
os.makedirs(os.path.join(ROOT, "one.example.com-2026-11-01-090000"))
# The file list, answered to the attacker and to staff
with open(os.path.join(ROOT, "one.example.com-2026-11-21-090000", "fmdapi.log"), "w") as f:
    f.write("Timestamp\tError\tLevel\tIP_Address\tUser\tHTTP\tMessage\tUsage\n")
    f.write("2026-11-20 03:00:00.000 +1100\t0\tINFO\t198.51.100.1\t\tGET\t/fmi/data/vLatest/databases\t100\n")
    f.write("2026-11-20 03:00:01.000 +1100\t214\tINFO\t198.51.100.1\t\tPOST\t/fmi/data/vLatest/databases/Sales/sessions\t100\n")
    f.write("2026-11-20 10:30:00.000 +1100\t0\tINFO\t203.0.113.5\t\tGET\t/fmi/data/vLatest/databases\t100\n")

names = []
r = S.sweep(ROOT, ["203.0.113.7"], ["Office iMac"], lookups=False, progress=lambda i, n, h: names.append(h))
check("sweep: reads the newest download of each server once", r["servers_read"] == 3 and r["folders_read"] == 3
      and sorted(names) == sorted(SERVERS))
at = {x["address"]: x for x in r["attackers"]}
check("attack: the sustained attack is one address across both servers, never signed in",
      list(at) == ["198.51.100.1"] and len(at["198.51.100.1"]["servers"]) == 2 and not at["198.51.100.1"]["signed_in"]
      and at["198.51.100.1"]["n"] == 150)
check("attack: its emails are counted, and the reasons say why it's an attack",
      at["198.51.100.1"]["emails"] == 60 and "admin-type names" in at["198.51.100.1"]["why"]
      and "email addresses nobody here signs in with" in at["198.51.100.1"]["why"])
check("attack: the file list it was given and the refusals for too many tries are counted",
      at["198.51.100.1"]["file_lists_answered"] == 1 and at["198.51.100.1"]["too_many"] == 1)
c = r["campaigns"]
check("campaign: 12 addresses in one hour across three time zones are one campaign",
      len(c) == 1 and c[0]["addresses"] == 12 and c[0]["tries"] == 24 and len(c[0]["servers"]) == 3)
check("campaign: the file name tried as an account name is shown as built from the server",
      ["sales", 12] in c[0]["tailored"])
check("campaign: its addresses aren't listed again as probes", not any(x["address"].startswith("192.0.2.") for x in r["probes"]))
check("signed in: many admin-type names, then a sign-in, is the one that matters most",
      [x["address"] for x in r["signed_in"]] == ["198.51.100.9", "198.51.100.80"]
      and r["signed_in"][0]["signed_in"][0]["accounts"] == ["admin"])
everyone = {x["address"] for k in ("attackers", "signed_in", "probes") for x in r[k]}
check("staff: a mistyped password then a sign-in isn't an attack", "203.0.113.5" not in everyone)
check("staff: a school network with 30 names and two Admin tries isn't an attack", "203.0.113.6" not in everyone)
check("verified: by address and by computer, left out and counted",
      not everyone & {"203.0.113.7", "203.0.113.8"} and r["summary"]["left_out"]["verified"] == 60)
check("private: the server itself and private addresses are left out", r["summary"]["left_out"]["private"] == 60
      and not everyone & {"127.0.0.1", "10.0.0.4"})
check("guest: a Guest sign-in through WebDirect is listed", [(g["address"], g["webdirect"]) for g in r["guest"]]
      == [("198.51.100.40", True)])
srv = {t["server"]: t for t in r["servers"]}
check("servers: the file list given to an address that never signed in is counted, staff's isn't",
      srv["one.example.com"]["file_list_to_outsiders"] == 1)
check("servers: every server with attack failures is counted", r["summary"]["servers_hit"] == 3)

a1 = at["198.51.100.1"]
check("activity: when it started, where first, each day, every server in order, and whether it was still going",
      a1["first_server"] == "two.example.com" and len(a1["timeline"]) == 2 and a1["timeline"][0][0] == "two.example.com"
      and sum(n for _, n in a1["daily"]) == 150 and a1["logs_end"] and a1["quiet_days"] >= 0)
check("activity: logs downloaded more than a day after its last try cover that quiet time, so it stopped on both servers",
      a1["ongoing"] == [] and sorted(x[0] for x in a1["stopped"]) == ["one.example.com", "two.example.com"])
check("dates: each server's download, the attacker's servers' downloads, and when the attacks started and were last seen",
      srv["one.example.com"]["downloaded"] == "2026-11-21 09:00" and a1["timeline"][0][4] == "2026-11-21 09:00"
      and a1["downloaded_newest"] == "2026-11-21 09:00" and r["summary"]["attacks_from"] <= a1["first"]
      and r["summary"]["attacks_to"] >= a1["last"] and r["summary"]["downloaded_oldest"] == "2026-11-21 09:00"
      and r["campaigns"][0]["downloaded_newest"] == "2026-11-21 09:00")
blk = {x["address"]: x for x in r["block"]}
check("block: the attackers that signed in come first, then the sustained attack, all Block now",
      [x["address"] for x in r["block"]][:3] == ["198.51.100.9", "198.51.100.80", "198.51.100.1"]
      and blk["198.51.100.1"]["priority"] == "Block now" and blk["198.51.100.9"]["signed_in"])
check("block: staff, verified computers, private addresses and the campaign aren't on it",
      not set(blk) & {"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8", "10.0.0.4", "127.0.0.1"}
      and not any(a.startswith("192.0.2.") and a != "192.0.2.200" for a in blk))
check("block: each says why, and the campaign keeps every address for a block list",
      "150 failed sign-ins on 2 servers" in blk["198.51.100.1"]["why"] and "admin-type names" in blk["198.51.100.1"]["why"]
      and len(r["campaigns"][0]["all_addresses"]) == 12)
runs = {(x["server"], x["account"]): x for x in r["failed_then_signed_in"]}
check("failed then signed in: the attacker's admin run is High, from an attacking address",
      runs.get(("three.example.com", "admin"), {}).get("risk") == "High" and runs[("three.example.com", "admin")]["attempts"] == 6)
check("failed then signed in: three wrong passwords from the same address, then in, is Low",
      runs.get(("one.example.com", "mia"), {}).get("risk") == "Low" and runs[("one.example.com", "mia")]["attempts"] == 3)
check("failed then signed in: one wrong password across five files is one attempt, so not listed",
      ("one.example.com", "mark") not in runs)
check("failed then signed in: 12 attempts in half an hour is Medium, as guessing",
      runs.get(("two.example.com", "cfo"), {}).get("risk") == "Medium" and runs[("two.example.com", "cfo")]["peak_hour"] == 12)
check("failed then signed in: counted by risk in the summary", r["summary"]["failed_then_signed_in"]["High"] == 1)
one = srv["one.example.com"]["addresses"]
lab = {x["address"]: x["label"] for x in one}
check("per server: each address with 2+ failures, the most first, labelled",
      one[0]["address"] == "198.51.100.1" and lab["198.51.100.1"] == "sustained attack" and lab.get("203.0.113.7") == "verified"
      and "203.0.113.5" not in lab)

si = {x["address"]: x for x in r["signed_in"]}
check("signed in first: in as admin, then three other admin-type names, is attacked-then-signed-in",
      "198.51.100.80" in si and "signed in as admin" in si["198.51.100.80"]["why"]
      and "signed in before the failures started" in si["198.51.100.80"]["why"])
check("signed in first: it's on the block list, Block now, marked signed in",
      blk.get("198.51.100.80", {}).get("priority") == "Block now" and blk["198.51.100.80"]["signed_in"])
check("signed in first: its label on the server says so", {x["address"]: x["label"] for x in
      srv["three.example.com"]["addresses"]}.get("198.51.100.80") == "attacked, then signed in")
pr = {x["address"]: x for x in r["probes"]}
check("file after file: ordinary names on 12 files, never signed in, is listed with the files as the reason",
      "198.51.100.60" in pr and "12 files" in pr["198.51.100.60"]["why"] and pr["198.51.100.60"]["many_files"] == 12)
check("file after file: it's on the block list, and the reason names the files",
      blk.get("198.51.100.60", {}).get("priority") == "Block now" and "12 files, one after another" in blk["198.51.100.60"]["why"])
check("file after file: an old device retrying a real person's name isn't listed", "203.0.113.41" not in everyone)
check("file after file: one wrong password across eight files is one attempt, so not listed", "203.0.113.42" not in everyone)
check("file after file: the reasons also name the files for an address listed for its names",
      "4 files" in at["198.51.100.1"]["why"])

own = S.block_list([], [], [{"address": "198.51.100.70", "n": 30, "servers": [["one.example.com", 30]], "first": "", "last": "",
                              "admin_type": 30, "owner": {"rdns": "fmclient3.example.com"}, "quiet_days": 2},
                             {"address": "198.51.100.71", "n": 30, "servers": [["one.example.com", 30]], "first": "", "last": "",
                              "admin_type": 30, "owner": {"rdns": "home.isp.net"}, "quiet_days": 400}],
                    own=frozenset(S.host_words("one.example.com", [])))
check("block: a name matching the servers' own domain looks like yours; one quiet for over 90 days is seen long ago",
      [x["priority"] for x in own] == ["Looks like yours", "Seen long ago"])

# The cache: a second sweep reads nothing new; a new download replaces its server's old summary
r2 = S.sweep(ROOT, ["203.0.113.7"], ["Office iMac"], lookups=False)
check("cache: a second sweep reads no folder again and gives the same answer",
      r2["folders_read"] == 0 and r2["summary"] == r["summary"])
shutil.copytree(os.path.join(ROOT, "two.example.com-2026-11-21-090000"), os.path.join(ROOT, "two.example.com-2026-11-22-090000"))
r3 = S.sweep(ROOT, lookups=False)
cached = sorted(os.listdir(os.path.join(ROOT, ".sweep-cache")))
check("cache: a new download is read, and the old one's summary removed",
      r3["folders_read"] == 1 and "two.example.com-2026-11-21-090000.json" not in cached and len(cached) == 3)

# Only the servers chosen are read; the log list says when each was downloaded and what a review has read
r5 = S.sweep(ROOT, lookups=False, hosts=["one.example.com"])
check("hosts: only the chosen servers are reviewed", r5["servers_read"] == 1 and r5["hosts"] == ["one.example.com"])
logs = {x["host"]: x for x in S.list_logs(ROOT)}
check("log list: every server's newest download, when, how many downloads, and its dates once read",
      sorted(logs) == sorted(SERVERS) and logs["one.example.com"]["downloads"] == 2
      and logs["one.example.com"]["downloaded"] == "2026-11-21 09:00" and logs["two.example.com"]["read"]
      and logs["two.example.com"]["folder"].endswith("2026-11-22-090000") and logs["one.example.com"]["from"])

# Owners: reverse DNS for each address that matters, RDAP for the busiest, networks for a campaign
r4 = S.sweep(ROOT, lookups=True, resolver=lambda ip: f"ec2-{ip.replace('.', '-')}.us-west-2.compute.amazonaws.com",
             registry=lambda ip: {"network": "TEST-NET", "org": "Example Org", "country": "US"})
a4 = {x["address"]: x for x in r4["attackers"]}["198.51.100.1"]
check("owners: the attacker's reverse DNS and registry are shown", a4["owner"]["org"] == "Example Org"
      and a4["owner"]["rdns"].endswith("amazonaws.com"))
check("owners: the campaign's networks are counted", r4["campaigns"][0]["networks"][0] == ["us-west-2.compute.amazonaws.com", 12])
check("owners: a sample of the campaign's addresses is kept, no more", len(r4["campaigns"][0]["sample"]) <= 12)

# The command: reads and removes the job, writes the result whole
job, out = os.path.join(ROOT, "sweep-logs-job.json"), os.path.join(ROOT, "sweep-logs-result.json")
with open(job, "w") as f:
    json.dump({"logs": ROOT, "verified_addresses": ["203.0.113.7"], "lookups": False}, f)
sys.argv = ["fms_log_sweep.py", job, out]
S.main()
done = json.load(open(out))
check("command: the job is removed and the result written whole", not os.path.exists(job) and done["ok"]
      and done["summary"]["attackers"] == 1 and not os.path.exists(out + ".part"))
check("names: an account name that looks like a typed password is hidden",
      S.hide_typed_password("Secret99Pass") != "Secret99Pass")

# The skill's command line: a folder of servers, one as a folder named for it and one as a .zip, never changed
import subprocess  # noqa: E402
import zipfile  # noqa: E402
LOGS = tempfile.mkdtemp(prefix="fms_sweep_cli_")
shutil.copytree(os.path.join(ROOT, "three.example.com-2026-11-21-090000"), os.path.join(LOGS, "three.example.com"))
with zipfile.ZipFile(os.path.join(LOGS, "one.example.com.zip"), "w") as z:
    for name in ("Event.log", "Access.log", "fmdapi.log"):
        z.write(os.path.join(ROOT, "one.example.com-2026-11-21-090000", name), "Logs/" + name)
before = sorted(os.listdir(LOGS))
cli_out = os.path.join(ROOT, "review.json")
p = subprocess.run([sys.executable, os.path.join(HERE, "fms_log_sweep.py"), "--logs", LOGS, "--out", cli_out],
                   capture_output=True, text=True)
check("command line: reads a folder and a .zip named for their servers, and prints a short summary",
      p.returncode == 0 and "2 servers" in p.stdout and len(p.stdout) < 6000 or print(p.stdout[-800:], p.stderr[-800:]))
check("command line: the attacker that signed in first is listed as attacked, then signed in",
      "## Attacked, then signed in: 2" in p.stdout and "198.51.100.80" in p.stdout and "signed in before the failures started" in p.stdout)
check("command line: everything is written to --out, and the logs folder is left as it was",
      json.load(open(cli_out))["servers_read"] == 2 and sorted(os.listdir(LOGS)) == before)
top = p.stdout.split("# The lists behind it")[0]
check("command line: the report opens as the scanner app's does, with the counts and the sign-in line",
      top.startswith("# Global Report: 2 servers") and "failed sign-ins that look like attacks, of" in top
      and "accounts failed, then signed in: high / worth a look" in top and "attacking addresses also signed in" in top)
todo = top.split("## What to do")[1]
check("command line: What to do, numbered and worst first, the attackers that signed in first",
      todo.lstrip().startswith("1. **Confirm today who signed in to admin") and "198.51.100.80" in todo.split("\n3.")[0]
      and "**Block the addresses below**" in todo and todo.rstrip().splitlines()[-1].endswith("left out of the next check."))
check("times read as the app shows them", S.when("2026-11-22 15:47") == "22 Nov 2026, 3:47 pm"
      and S.when("2026-01-05 09:05") == "5 Jan 2026, 9:05 am" and S.when("") == "")
check("command line: no lookups unless asked", "rdns" not in json.dumps(json.load(open(cli_out))["block"]))
p2 = subprocess.run([sys.executable, os.path.join(HERE, "fms_log_sweep.py"), "--logs", os.path.join(LOGS, "nowhere")],
                    capture_output=True, text=True)
check("command line: a missing folder says what --logs needs", p2.returncode != 0 and "isn't a folder" in p2.stderr)
shutil.rmtree(LOGS)

shutil.rmtree(ROOT)
print(f"\n{sum(results)} of {len(results)} passed")
sys.exit(0 if all(results) else 1)
