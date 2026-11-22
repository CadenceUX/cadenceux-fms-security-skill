#!/usr/bin/env python3
"""Global log review: several servers' logs read together, for the attacks no single server shows.

    python3 fms_log_sweep.py --logs <folder> [--out <result.json>] [--verified-addresses a,b]
                             [--verified-computers name,name] [--lookups]
    python3 fms_log_sweep.py [job.json] [result.json]      (the FMS Scanner app's form)

--logs is a folder holding one sub-folder or .zip per server, named for the server (fms1.example.com or
fms1.example.com.zip); a download folder named <server>-YYYY-MM-DD-HHMMSS also works, and the newest per server is
used. Each holds that server's Event, Access, fmdapi and fmodata logs. It prints a short summary (about 3 KB) and
writes everything to --out (default: global-review.json in the current folder). --lookups looks up who owns each
attacking address (reverse DNS, and RDAP for the busiest); without it nothing leaves this machine.

The FMS Scanner app starts it through fms_scan_runner.py --sweep-logs, with a job file, and it reads the newest
download of each server in ~/Desktop/fms-security/logs. Either way it reports:

  attackers   addresses that failed to sign in the way attack tools do (admin-type names, many names, many files,
              many servers, a high rate, or names built from the server's own files and hostname), with whether they
              ever signed in anywhere
  campaigns   hours when many addresses failed a few times each across the servers: the rotating-address attacks in
              Claris's "Lock Down Your FileMaker Server" guide, section 5
  servers     each server's failures, attackers, and whether it gave its file list to addresses that never signed in
  guest       Guest sign-ins, which never show as failures

The job (optional) names the verified addresses and computers to leave out, and whether to look up who owns each
address (reverse DNS, and RDAP for the busiest). Each download folder's summary is cached in logs/.sweep-cache, because
a folder never changes once it's downloaded, so a second sweep only reads new downloads. Standard library only; no
model is involved. Read-only: it never changes the logs.
"""
import collections
import concurrent.futures
import datetime
import glob
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
# Beside fms_logcheck.py in the skill's scripts folder; in the scanner app's runner, the skill sits in skill/scripts
sys.path.insert(0, os.path.join(HERE, "skill", "scripts"))
sys.path.insert(0, HERE)
from fms_logcheck import GENERIC, hide_typed_password  # noqa: E402

LOGS_ROOT = "~/Desktop/fms-security/logs"
CACHE_VERSION = 7
FOLDER = re.compile(r"^(?P<host>.+)-(?P<when>\d{4}-\d\d-\d\d-\d{6})$")
STAMP = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? ([+-]\d{4})\t")
EVENT_FAILED = re.compile(r'Client "(?P<client>.*?)(?: \((?P<pc>[^()]*)\))? \[(?P<ip>[^\]]+)\]" authentication failed on database '
                          r'"(?P<file>[^"]+)" using "(?:(?P<acct>[^"]*?) )?\[(?P<via>\w+)\]"')
ADMIN_FAILED = re.compile(r'Administrator authentication failed: "(?P<acct>.*?) \[(?P<ip>[^\]]+)\]"')
OPENED = re.compile(r'Client "(?P<client>.*?)(?: \((?P<pc>[^()]*)\))? \[(?P<ip>[^\]]+)\]" opening database "(?P<file>[^"]*)" as "(?P<acct>[^"]*)"')
FILE_LIST = re.compile(r"^/fmi/(?:data/[^/]+/databases|odata/v\d+)/?$")
SIGN_IN = re.compile(r"/sessions/?$")
DOORS = {"fmapp": "FileMaker Pro/Go", "fmwebdirect": "WebDirect", "fmrest": "Data API", "fmodata": "OData",
         "fmxdbc": "ODBC/JDBC", "fmxml": "XML", "fmphp": "PHP", "admin-console": "Admin Console"}
# Parts of a hostname that say nothing about the customer: a name built from the rest is guessed from the server
PLAIN_LABELS = {"com", "net", "org", "edu", "gov", "au", "nz", "uk", "us", "ca", "co", "io", "www", "fms", "fm",
                "filemaker", "server", "nsw", "vic", "qld", "wa", "sa", "act", "tas", "nt"}
RATE = 20             # failures from one address in 10 minutes, as fms_logcheck's RATE
SUSTAINED = 100       # failures, or 20+ account names: an attack rather than a probe
CAMPAIGN_TRIES = 6    # an address making this many tries or fewer, never signing in, can be part of a rotating sweep
CAMPAIGN_ADDRESSES = 10   # ...and an hour with this many such addresses, across every server, is a campaign hour
CAMPAIGN_MEMBER = 15  # once an hour is a campaign's, an address with up to this many tries in it belongs to the campaign
LOOKUPS = 60          # addresses whose owner is looked up (reverse DNS); the busiest 15 also get RDAP
TIMEOUT = 8
RUN_ATTEMPTS = 3      # failed attempts on one account, then a sign-in to it: listed under "failed, then signed in"
RUN_HOURS = 24        # ...counting only the failures in the day before that sign-in
SAME_ATTEMPT = 10     # failures from one address within this many seconds are one attempt: a multi-file
                      # solution fails once per file for a single wrong password
PER_SERVER = 40       # addresses with 2+ failed sign-ins shown for each server, the most failures first
MANY_FILES = 3        # files one address failed on, as fms_logcheck's MANY-FILES: the pattern in Claris's lockdown
                      # guide is one address going file after file
FILE_ATTEMPTS = 3     # ...in this many separate attempts, so one wrong password across a multi-file solution isn't it


def utc(local, offset):
    """'2026-11-12 03:20:34' at '+1100' -> a UTC datetime."""
    t = datetime.datetime.strptime(local, "%Y-%m-%d %H:%M:%S")
    sign = 1 if offset[0] == "+" else -1
    return t - sign * datetime.timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def lines(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            yield from f


def computer_of(client, pc, host):
    """The computer behind a failure or sign-in, as fms_scan_runner names it, for matching verified computers."""
    device = f"{client} on {pc}" if client and pc else (pc or client or "")
    name = device.rsplit(" on ", 1)[-1].strip().strip("[]()")
    if not name or name.lower() == "localhost" or name.startswith("WebDirect-") or name.lower() == host.lower():
        return ""
    return name


def read_folder(folder, host):
    """One download folder's summary: failures, sign-ins and Data API/OData use per address, times in UTC."""
    fails, signins, api, files = {}, {}, {}, set()
    first = last = access_from = None
    by_account, opened_as = collections.defaultdict(list), collections.defaultdict(list)
    offset = "+0000"
    for name in ("Event-old.log", "Event.log"):
        for l in lines(os.path.join(folder, name)):
            if "authentication failed" not in l:
                continue
            s = STAMP.match(l)
            if not s:
                continue
            offset = s.group(2)
            m = EVENT_FAILED.search(l)
            a = None if m else ADMIN_FAILED.search(l)
            if not (m or a):
                continue
            t = utc(s.group(1), s.group(2))
            ip = (m or a).group("ip")
            acct = ((m or a).group("acct") or "")
            door = m.group("via").lower() if m else "admin-console"
            r = fails.setdefault(ip, {"n": 0, "hours": collections.Counter(), "win": collections.Counter(),
                                      "accts": collections.Counter(), "files": collections.Counter(),
                                      "doors": collections.Counter(), "computers": set(), "first": t, "last": t,
                                      "attempts": 0, "began": None})
            r["n"] += 1
            # An attempt is the failures within SAME_ATTEMPT seconds of its first, as in failed_then_signed_in
            if r["began"] is None or abs((t - r["began"]).total_seconds()) > SAME_ATTEMPT:
                r["attempts"] += 1
                r["began"] = t
            r["hours"][t.strftime("%Y-%m-%dT%H")] += 1
            r["win"][t.strftime("%Y-%m-%dT%H:%M")[:-1]] += 1
            r["accts"][acct] += 1
            r["doors"][door] += 1
            r["first"], r["last"] = min(r["first"], t), max(r["last"], t)
            if acct and door != "admin-console":
                by_account[acct.lower()].append((t, ip, acct))
            if m:
                r["files"][m.group("file")] += 1
                files.add(m.group("file"))
                pc = computer_of(m.group("client"), m.group("pc"), host)
                if pc:
                    r["computers"].add(pc)
            first, last = min(first or t, t), max(last or t, t)
    for name in ("Access-old.log", "Access.log"):
        for l in lines(os.path.join(folder, name)):
            if "opening database" not in l:
                continue
            m = OPENED.search(l)
            s = STAMP.match(l)
            if not (m and s):
                continue
            t = utc(s.group(1), s.group(2))
            access_from = min(access_from or t, t)
            files.add(m.group("file"))
            r = signins.setdefault(m.group("ip"), {"n": 0, "accts": collections.Counter(), "computers": set(),
                                                    "first": t, "last": t, "guest": None})
            r["n"] += 1
            r["accts"][m.group("acct")] += 1
            r["first"], r["last"] = min(r["first"], t), max(r["last"], t)
            pc = computer_of(m.group("client"), m.group("pc"), host)
            if pc:
                r["computers"].add(pc)
            if m.group("acct").lower() in by_account:
                opened_as[m.group("acct").lower()].append((t, m.group("ip")))
            if m.group("acct") == "[Guest]":
                g = r["guest"] = r["guest"] or {"n": 0, "files": set(), "webdirect": False, "first": t, "last": t}
                g["n"] += 1
                g["files"].add(m.group("file"))
                g["webdirect"] = g["webdirect"] or "WebDirect-" in m.group("client")
                g["first"], g["last"] = min(g["first"], t), max(g["last"], t)
            first, last = min(first or t, t), max(last or t, t)
    for name in ("fmdapi-old.log", "fmdapi.log", "fmodata-old.log", "fmodata.log"):
        for l in lines(os.path.join(folder, name)):
            f = l.rstrip("\n").split("\t")
            if len(f) < 7 or not f[0][:4].isdigit():
                continue
            ip, err, method, path = f[3], f[1].strip(), f[5].upper(), f[6].split("?")[0]
            r = api.setdefault(ip, {"calls": 0, "lists": 0, "lists_ok": 0, "refused": 0, "too_many": 0, "ok_users": collections.Counter()})
            r["calls"] += 1
            if method == "GET" and FILE_LIST.match(path):
                r["lists"] += 1
                r["lists_ok"] += err == "0"
            if method == "POST" and SIGN_IN.search(path):
                if err == "0":
                    r["ok_users"][f[4].strip() or "(no name)"] += 1
                else:
                    r["refused"] += 1
                    r["too_many"] += err == "214"
    out = {"version": CACHE_VERSION, "host": host, "folder": os.path.basename(folder), "offset": offset,
           "from": iso(first) if first else "", "to": iso(last) if last else "",
           "access_from": iso(access_from) if access_from else "",
           "hosted": sorted(files), "fails": {}, "signins": {}, "api": api}
    for ip, r in fails.items():
        out["fails"][ip] = {"n": r["n"], "attempts": r["attempts"], "hours": dict(r["hours"]), "peak10": max(r["win"].values()),
                            "accts": dict(r["accts"]), "files": dict(r["files"]), "doors": dict(r["doors"]),
                            "computers": sorted(r["computers"]), "first": iso(r["first"]), "last": iso(r["last"])}
    for ip, r in signins.items():
        g = r["guest"]
        out["signins"][ip] = {"n": r["n"], "accts": dict(r["accts"].most_common(8)), "computers": sorted(r["computers"])[:20],
                              "first": iso(r["first"]), "last": iso(r["last"]),
                              "guest": g and {"n": g["n"], "files": sorted(g["files"]), "webdirect": g["webdirect"],
                                              "first": iso(g["first"]), "last": iso(g["last"])}}
    for r in api.values():
        r["ok_users"] = dict(r["ok_users"])
    out["runs"] = failed_then_signed_in(by_account, opened_as)
    return out


def failed_then_signed_in(by_account, opened_as):
    """Runs of failed sign-ins on one account that end with a sign-in to it: the day's failures before each first
    sign-in after them. A person mistyping fails from the address they then sign in from; a guessed password fails
    from many, or signs in from somewhere new."""
    runs = []
    for acct, fl in by_account.items():
        signs = sorted(opened_as.get(acct, []))
        if not signs:
            continue
        fl.sort()
        i, pending = 0, []
        for t, ip in signs:
            while i < len(fl) and fl[i][0] <= t:
                pending.append(fl[i])
                i += 1
            pending = [f for f in pending if (t - f[0]).total_seconds() <= RUN_HOURS * 3600]
            if not pending:
                continue
            # An attempt is the failures one address makes within SAME_ATTEMPT seconds of the attempt's first:
            # one wrong password across a multi-file solution. A tool firing without a pause makes one every 10 seconds
            attempts, began, times = collections.Counter(), {}, []
            for ft, fip, _ in pending:
                if fip not in began or (ft - began[fip]).total_seconds() > SAME_ATTEMPT:
                    attempts[fip] += 1
                    times.append(ft)
                    began[fip] = ft
            # The most attempts in any hour: guessing is fast, a device with an old saved password retries slowly
            peak, j = 0, 0
            for k, ft in enumerate(times):
                while (ft - times[j]).total_seconds() > 3600:
                    j += 1
                peak = max(peak, k - j + 1)
            if sum(attempts.values()) >= RUN_ATTEMPTS:
                runs.append({"account": collections.Counter(a for _, _, a in pending).most_common(1)[0][0],
                             "attempts": sum(attempts.values()), "failures": len(pending), "addresses": dict(attempts),
                             "first": iso(pending[0][0]), "signed_in": iso(t), "signed_in_from": ip, "peak_hour": peak})
            pending = []
            if i >= len(fl):
                break
    return runs


def newest_folders(root):
    """The newest download folder of each server: OttoFMS downloads the whole current log each time."""
    newest, plain = {}, {}
    for path in sorted(glob.glob(os.path.join(root, "*", ""))):
        name = os.path.basename(path.rstrip("/"))
        m = FOLDER.match(name)
        if m:
            newest[m.group("host")] = path.rstrip("/")
        elif not name.startswith("."):
            plain[name] = path.rstrip("/")    # a folder named for its server alone, as the skill's --logs takes them
    for host, path in plain.items():
        newest.setdefault(host, path)
    return newest


def summaries(root, progress=None, hosts=None):
    cache = os.path.join(root, ".sweep-cache")
    os.makedirs(cache, mode=0o700, exist_ok=True)
    found, read = [], 0
    every = newest_folders(root)
    folders = {h: f for h, f in every.items() if hosts is None or h in hosts}
    for i, (host, folder) in enumerate(sorted(folders.items())):
        saved = os.path.join(cache, os.path.basename(folder) + ".json")
        s = None
        if os.path.exists(saved):
            try:
                with open(saved, encoding="utf-8") as f:
                    s = json.load(f)
            except (OSError, ValueError):
                s = None
            if s and s.get("version") != CACHE_VERSION:
                s = None
        if s is None:
            s = read_folder(folder, host)
            read += 1
            with open(saved, "w", encoding="utf-8") as f:
                json.dump(s, f)
        if progress:
            progress(i + 1, len(folders), host)
        found.append(s)
    # Caches of folders no longer the newest are removed, so the cache never outgrows the logs
    keep = {os.path.basename(f) + ".json" for f in every.values()}
    for old in os.listdir(cache):
        if old.endswith(".json") and old not in keep:
            os.remove(os.path.join(cache, old))
    return found, read


# Networks that never reach a server from the internet: the server itself, office LANs, carrier NAT, IPv6 local
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                             "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def list_logs(root=LOGS_ROOT):
    """Each server's newest download: when it was downloaded, and the dates its logs cover once a Global Report has read it."""
    root = os.path.expanduser(root)
    cache = os.path.join(root, ".sweep-cache")
    found = []
    counts = collections.Counter(FOLDER.match(os.path.basename(p.rstrip("/"))).group("host")
                                 for p in glob.glob(os.path.join(root, "*", "")) if FOLDER.match(os.path.basename(p.rstrip("/"))))
    for host, folder in sorted(newest_folders(root).items()):
        name = os.path.basename(folder)
        when = FOLDER.match(name).group("when")
        row = {"host": host, "folder": name, "downloaded": f"{when[:10]} {when[11:13]}:{when[13:15]}", "downloads": counts[host],
               "from": "", "to": "", "read": False}
        try:
            with open(os.path.join(cache, name + ".json"), encoding="utf-8") as f:
                s = json.load(f)
            row.update({"from": local(s.get("from", "")), "to": local(s.get("to", "")), "read": True})
        except (OSError, ValueError):
            pass
        found.append(row)
    return found


def downloaded(folder):
    """When a download folder was made, from its name: 'host-2026-11-20-154343' -> '2026-11-20 15:43' (this Mac's time)."""
    m = FOLDER.match(folder or "")
    w = m.group("when") if m else ""
    return f"{w[:10]} {w[11:13]}:{w[13:15]}" if w else ""


def downloaded_utc(folder):
    """The download time as a UTC stamp. OttoFMS copies the live logs, so they cover everything up to that moment, even
    when the last line the review reads (a failure or a sign-in) is much older."""
    d = downloaded(folder)
    if not d:
        return ""
    return iso(datetime.datetime.strptime(d, "%Y-%m-%d %H:%M").astimezone(datetime.timezone.utc).replace(tzinfo=None))


def public(ip):
    try:
        a = ipaddress.ip_address(ip.replace("::ffff:", ""))
    except ValueError:
        return False
    return not any(a.version == n.version and a in n for n in PRIVATE)


def is_generic(name):
    return name.lower() in GENERIC and name != ""


def host_words(host, hosted):
    """Account names an attacker can build from the server itself: its file names and hostname."""
    words = {re.sub(r"\.fmp12$", "", f, flags=re.I).lower() for f in hosted}
    words |= {w for w in re.split(r"[.\-]", host.lower()) if len(w) > 2 and w not in PLAIN_LABELS}
    return words


def local(stamp):
    """A UTC stamp in this Mac's own time, as people read it."""
    if not stamp:
        return ""
    t = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return t.astimezone().strftime("%Y-%m-%d %H:%M")


def local_hour(hour):
    t = datetime.datetime.strptime(hour, "%Y-%m-%dT%H").replace(tzinfo=datetime.timezone.utc)
    return t.astimezone().strftime("%Y-%m-%d %H:00")


def network(rdns):
    """'ec2-44-252-29-246.us-west-2.compute.amazonaws.com' -> 'us-west-2.compute.amazonaws.com'."""
    parts = rdns.rstrip(".").split(".")
    return ".".join(parts[1:]) if len(parts) > 3 else ".".join(parts)


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def rdap(ip):
    """The network's owner from RDAP (the registries' own lookup service): name, organisation and country."""
    try:
        req = urllib.request.Request("https://rdap.org/ip/" + ip, headers={"Accept": "application/rdap+json",
                                                                          "User-Agent": "fms-log-sweep"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            d = json.load(r)
    except (OSError, ValueError):
        return {}
    org = ""
    for e in d.get("entities") or []:
        for item in (e.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn" and "registrant" in (e.get("roles") or []) or (item and item[0] == "fn" and not org):
                org = item[3]
    return {"network": d.get("name", ""), "org": org, "country": d.get("country", "")}


def owners(ips, busiest, resolver=reverse_dns, registry=rdap):
    found = {}
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        for ip, name in zip(ips, pool.map(resolver, ips)):
            found[ip] = {"rdns": name}
        for ip, info in zip(busiest, pool.map(registry, busiest)):
            found.setdefault(ip, {}).update(info)
    return found


def activity(r, log_end, got=None):
    """When an address started, each day's failures, each server in the order it reached them, and whether it was still
    at it when those servers' logs end. Ongoing means a failure within a day of the end of a server's log."""
    days = collections.Counter()
    for hour, n in r["hours"].items():
        days[local_hour(hour)[:10]] += n
    servers = sorted(r["per_server"].items(), key=lambda x: x[1][0])
    ends = [log_end.get(h, "") for h, _ in servers if log_end.get(h)]
    def gap(h, last):
        return (datetime.datetime.strptime(log_end[h], "%Y-%m-%dT%H:%M:%SZ")
                - datetime.datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ")).total_seconds() / 86400
    # Still at it when a server's log ends: whether it carried on there is unknown until newer logs are downloaded.
    # Stopped: that server's log runs on for more than a day after its last failure there
    ongoing = [h for h, (first, last, n) in servers if log_end.get(h) and gap(h, last) <= 1]
    stopped = [[h, local(log_end[h]), round(gap(h, last), 1)] for h, (first, last, n) in servers
               if log_end.get(h) and gap(h, last) > 1]
    end = max(ends) if ends else ""
    quiet = 0.0
    if end and r["last"]:
        quiet = (datetime.datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
                 - datetime.datetime.strptime(r["last"], "%Y-%m-%dT%H:%M:%SZ")).total_seconds() / 86400
    got = got or {}
    when_got = [got[h] for h, _ in servers if got.get(h)]
    return {"daily": sorted([d, n] for d, n in days.items()),
            "timeline": [[h, local(first), local(last), n, got.get(h, "")] for h, (first, last, n) in servers],
            "downloaded_newest": max(when_got) if when_got else "", "downloaded_oldest": min(when_got) if when_got else "",
            "first_server": servers[0][0] if servers else "", "logs_end": local(end),
            "ongoing": ongoing, "stopped": sorted(stopped, key=lambda x: x[2]), "quiet_days": round(max(quiet, 0.0), 1)}


OLD_DAYS = 90         # an address quiet this long is left off the block list: home addresses change hands


def block_list(signed_in, attackers, probes, own=frozenset()):
    """The addresses to block at the firewall, the most urgent first. Every one tried the names attack tools use, or
    went file after file with names nobody here uses, and none is verified or private. Block now: it signed in after attacking, attacked at length, reached three or more
    servers, made ten or more tries, or was still at it when a server's logs end. Block if you can: the rest."""
    rows = []
    for kind, group in (("attacked, then signed in", signed_in), ("sustained attack", attackers), ("probe", probes)):
        for x in group:
            if kind == "probe" and x["n"] < 3:
                continue    # one or two tries: too little to block on, and often a shared address such as iCloud Private Relay
            k = len(x["servers"])
            urgent = kind != "probe" or x["n"] >= 10 or k >= 3 or bool(x.get("ongoing"))
            why = [f"{x['n']:,} failed sign-in{'s' * (x['n'] != 1)} on {k} server{'s' * (k != 1)}"]
            if x.get("admin_type"):
                why.append("admin-type names")
            if x.get("tailored"):
                why.append("names built from the server's own files or hostname")
            if x.get("emails"):
                why.append("email addresses from breach lists")
            if x.get("many_files"):
                why.append(f"{x['many_files']} files, one after another")
            if x.get("file_lists_answered"):
                why.append("was given the file list")
            if kind == "attacked, then signed in":
                why.append("and signed in: confirm who it is before anything else")
            rows.append({"address": x["address"], "kind": kind, "priority": "Block now" if urgent else "Block if you can",
                         "why": ", ".join(why), "n": x["n"], "servers": k, "first": x["first"], "last": x["last"],
                         "ongoing": x.get("ongoing", []), "quiet_days": x.get("quiet_days", 0),
                         "owner": x.get("owner", {}), "signed_in": kind == "attacked, then signed in"})
    # An address whose name matches the servers' own domains (the hosting company's or a customer's own name) is most likely the host's
    # or a customer's own machine, and one quiet for months has probably changed hands: neither is for blocking
    for row in rows:
        name = (row["owner"] or {}).get("rdns", "")
        if name and set(re.split(r"[.\-]", name.lower())) & own and not row["signed_in"]:
            row["priority"], row["why"] = "Looks like yours", row["why"] + f". Its name, {name}, matches your servers' own domain"
        elif row["quiet_days"] > OLD_DAYS and not row["signed_in"]:
            row["priority"] = "Seen long ago"
    order = {"Block now": 0, "Block if you can": 1, "Looks like yours": 2, "Seen long ago": 3}
    rows.sort(key=lambda r: (order[r["priority"]], not r["signed_in"], not r["ongoing"], -r["n"]))
    return rows


def sweep(root, verified_addresses=(), verified_computers=(), lookups=True, progress=None,
          resolver=reverse_dns, registry=rdap, hosts=None):
    root = os.path.expanduser(root)
    servers, read = summaries(root, progress, set(hosts) if hosts else None)
    verified_addresses = {a.strip() for a in verified_addresses if a and a.strip()}
    verified_computers = {c.strip().lower() for c in verified_computers if c and c.strip()}
    words = {s["host"]: host_words(s["host"], s["hosted"]) for s in servers}

    # Every address across every server
    who = collections.defaultdict(lambda: {"n": 0, "attempts": 0, "servers": collections.Counter(), "accts": collections.Counter(),
                                           "files": collections.Counter(), "doors": collections.Counter(),
                                           "hours": collections.Counter(), "peak10": 0, "computers": set(),
                                           "first": "", "last": "", "tailored": collections.Counter(),
                                           "signed_in": [], "lists_ok": 0, "lists": 0, "too_many": 0,
                                           "before_access": [], "per_server": {}})
    for s in servers:
        for ip, f in s["fails"].items():
            r = who[ip]
            r["n"] += f["n"]
            r["attempts"] += f.get("attempts", 0)
            r["servers"][s["host"]] += f["n"]
            r["accts"].update(f["accts"])
            r["files"].update(f["files"])
            r["doors"].update(f["doors"])
            r["hours"].update(f["hours"])
            r["peak10"] = max(r["peak10"], f["peak10"])
            r["computers"].update(f["computers"])
            r["first"] = min(r["first"] or f["first"], f["first"])
            r["last"] = max(r["last"], f["last"])
            r["per_server"][s["host"]] = (f["first"], f["last"], f["n"])
            # Failures older than the server's Access log: a sign-in from then can't be ruled out
            if not s["access_from"] or f["first"] < s["access_from"]:
                r["before_access"].append(s["host"])
            for a, n in f["accts"].items():
                if a.lower() in words[s["host"]]:
                    r["tailored"][a.lower()] += n
        for ip, g in s["signins"].items():
            if ip in who:
                who[ip]["signed_in"].append({"server": s["host"], "n": g["n"], "accounts": list(g["accts"])[:5],
                                             "first": local(g["first"]), "last": local(g["last"])})
        for ip, a in s["api"].items():
            if ip in who:
                who[ip]["lists"] += a["lists"]
                who[ip]["lists_ok"] += a["lists_ok"]
                who[ip]["too_many"] += a["too_many"]
                for u, n in a["ok_users"].items():
                    who[ip]["signed_in"].append({"server": s["host"], "n": n, "accounts": [u + " (Data API)"],
                                                 "first": "", "last": ""})

    # The names attack tools use. A school's network can put a hundred staff behind one address, each mistyping their
    # own name, so how many names an address tried says little. What it tried says more: admin and its kind, names
    # built from the server's files or hostname, names many unrelated addresses share (a tool's list), and email
    # addresses at domains nobody here signs in with (lists from public data breaches).
    # Names and email domains people really use: signed in with, or failed from an address that also signed in
    real_names, real_domains = set(), set()
    for s in servers:
        for ip, g in s["signins"].items():
            for a in list(g["accts"]) + list(s["fails"].get(ip, {}).get("accts", {})):
                real_names.add(a.lower())
                if "@" in a:
                    real_names.add(a.lower().split("@")[0])
                    real_domains.add(a.lower().rsplit("@", 1)[1])
    sharers, spread = collections.defaultdict(set), collections.defaultdict(set)
    for ip, r in who.items():
        if public(ip) and not r["signed_in"]:
            for a in r["accts"]:
                sharers[a.lower()].add(ip)
                spread[a.lower()].update(r["servers"])
    # A tool's list reaches many servers from many addresses; a person's own name stays at their school
    shared = {a for a, ips in sharers.items() if len(ips) >= 5 and len(spread[a]) >= 3 and a and " " not in a
              and "@" not in a and a not in real_names}

    def attack_name(a):
        a = a.lower()
        return is_generic(a) or a in shared or ("@" in a and a.rsplit("@", 1)[1] not in real_domains and len(r_emails) >= 3)

    r_emails = []     # the current address's emails at unknown domains: three or more is a list, not a person

    def r_emails_of(r):
        return [a for a in r["accts"] if "@" in a and a.lower().rsplit("@", 1)[1] not in real_domains]
    left_out = collections.Counter()
    judged = {}
    for ip, r in who.items():
        if not public(ip):
            left_out["private"] += r["n"]
            continue
        if ip in verified_addresses or (r["computers"] and all(c.lower() in verified_computers for c in r["computers"])):
            left_out["verified"] += r["n"]
            continue
        r_emails[:] = [a for a in r["accts"] if "@" in a and a.lower().rsplit("@", 1)[1] not in real_domains]
        r["attack_n"] = sum(n for a, n in r["accts"].items() if attack_name(a) or a.lower() in r["tailored"])
        r["attack_names"] = sum(1 for a in r["accts"] if attack_name(a) or a.lower() in r["tailored"])
        generic = sum(n for a, n in r["accts"].items() if is_generic(a))
        reasons = []
        # File after file: 3+ files in 3+ separate attempts. Whatever the names, when it never signed in and tried a
        # name nobody here uses. A device with an old saved password retries a real person's name, so it isn't this
        many_files = len(r["files"]) >= MANY_FILES and r["attempts"] >= FILE_ATTEMPTS
        r["file_walk"] = many_files and not r["signed_in"] and any(a.lower() not in real_names for a in r["accts"])
        # Mostly attack names, or a lot of them: a few admin tries among a school's own names is staff
        if not ((r["attack_n"] >= 2 and r["attack_n"] * 2 >= r["n"]) or r["attack_names"] >= 10 or r["tailored"]
                or r["file_walk"]):
            judged[ip] = (r, reasons, generic)
            continue
        if generic:
            reasons.append("admin-type names")
        if r["tailored"]:
            reasons.append("names built from the server's own files or hostname")
        if any(a.lower() in shared for a in r["accts"]):
            reasons.append("names other attacking addresses also tried")
        if len({a.lower() for a in r["accts"] if "@" in a and a.lower().rsplit("@", 1)[1] not in real_domains}) >= 3:
            reasons.append("email addresses nobody here signs in with")
        if r["peak10"] >= RATE:
            reasons.append(f"{r['peak10']} tries in 10 minutes")
        if many_files:
            reasons.append(f"{len(r['files'])} files")
        if len(r["servers"]) >= 2 and not r["signed_in"]:
            reasons.append(f"{len(r['servers'])} servers")
        if reasons and len(r["doors"]) >= 3:
            reasons.append(f"{len(r['doors'])} ways in")
        judged[ip] = (r, reasons, generic)

    # Rotating-address campaigns: hours when many addresses, each with only a few tries and no sign-in, failed
    few = {ip for ip, (r, reasons, g) in judged.items() if r["n"] <= CAMPAIGN_TRIES and not r["signed_in"] and r["attack_n"]}
    by_hour = collections.defaultdict(set)
    for ip in few:
        for h in judged[ip][0]["hours"]:
            by_hour[h].add(ip)
    hot = sorted(h for h, ips in by_hour.items() if len(ips) >= CAMPAIGN_ADDRESSES)
    groups = []
    for h in hot:
        t = datetime.datetime.strptime(h, "%Y-%m-%dT%H")
        if groups and t - groups[-1][-1][1] <= datetime.timedelta(hours=2):
            groups[-1].append((h, t))
        else:
            groups.append([(h, t)])
    campaigns, in_campaign = [], set()
    for g in groups:
        hours = {h for h, _ in g}
        ips = {ip for ip, (r, _, _) in judged.items() if r["n"] <= CAMPAIGN_MEMBER and not r["signed_in"]
               and r["attack_n"] and set(r["hours"]) & hours}
        in_campaign |= ips
        names, servers_hit, tailored, tries = collections.Counter(), collections.Counter(), collections.Counter(), 0
        per = collections.Counter()
        times = []
        for ip in ips:
            r = judged[ip][0]
            names.update({a.lower(): n for a, n in r["accts"].items()})
            servers_hit.update(r["servers"])
            tailored.update(r["tailored"])
            tries += r["n"]
            per[r["n"]] += 1
            times += [r["first"], r["last"]]
        campaigns.append({"from": local(min(times)), "to": local(max(times)), "addresses": len(ips), "tries": tries,
                          "servers": [[h, n] for h, n in servers_hit.most_common()],
                          "names": [[hide_typed_password(a) if a else "(blank)", n] for a, n in names.most_common(15)],
                          "tailored": [[a, n] for a, n in tailored.most_common(12)],
                          "admin_type": sum(n for a, n in names.items() if is_generic(a)),
                          "tries_per_address": sorted([k, v] for k, v in per.items()),
                          "hours": [[local_hour(h), len(by_hour[h])] for h, _ in g],
                          "downloaded_newest": max(downloaded(x["folder"]) for x in servers if x["host"] in servers_hit),
                          "downloaded_oldest": min(downloaded(x["folder"]) for x in servers if x["host"] in servers_hit),
                          "sample": sorted(ips)})

    log_end = {s["host"]: max(s["to"], downloaded_utc(s["folder"])) for s in servers}
    got = {s["host"]: downloaded(s["folder"]) for s in servers}
    attackers, signed_in, probes = [], [], []
    for ip, (r, reasons, generic) in judged.items():
        if not reasons or ip in in_campaign:
            continue
        busiest_hour = max(r["hours"].items(), key=lambda x: x[1])
        row = {"address": ip, "n": r["n"], "servers": [[h, n] for h, n in r["servers"].most_common()],
               "doors": [[DOORS.get(d, d), n] for d, n in r["doors"].most_common()],
               "account_names": len(r["accts"]), "admin_type": generic,
               "emails": sum(r["accts"][a] for a in r_emails_of(r)),
               "before_access": r["before_access"],
               "top_names": [[hide_typed_password(a) if a else "(blank)", n] for a, n in r["accts"].most_common(12)],
               "tailored": [[a, n] for a, n in r["tailored"].most_common(8)],
               "files": len(r["files"]), "top_files": [[f, n] for f, n in r["files"].most_common(5)],
               "first": local(r["first"]), "last": local(r["last"]), "peak10": r["peak10"],
               "busiest_hour": [local_hour(busiest_hour[0]), busiest_hour[1]],
               "file_lists": r["lists"], "file_lists_answered": r["lists_ok"], "too_many": r["too_many"],
               "signed_in": r["signed_in"][:6], "why": reasons,
               "many_files": len(r["files"]) if f"{len(r['files'])} files" in reasons else 0}
        row["attack_tries"], row["attack_names"] = r["attack_n"], r["attack_names"]
        row.update(activity(r, log_end, got))
        if r["signed_in"]:
            # Many different attack names, and also a sign-in: the one that matters most. Fewer is a network people
            # work from: a support team trying Admin before their own name, staff mistyping theirs
            mine = {a.lower() for x in r["signed_in"] for a in x["accounts"]}
            distinct = {a.lower() for a in r["accts"] if (attack_name(a) or a.lower() in r["tailored"]) and a.lower() not in mine}
            row["attack_names"] = len(distinct)
            # Or it got in with an admin-type name and tried two or more others: an address that signed in as admin
            # over JDBC, then failed hundreds of times on six names. A support team signs in with its own names, not these.
            # The sign-in counts before or after the failures, as fms_logcheck's SIGNED-IN does
            got_in_as = sorted({a.replace(" (data api)", "") for a in mine} & {a for a in GENERIC if a})
            if r["attack_n"] >= 10 and (len(distinct) >= 4 or (got_in_as and len(distinct) >= 2)):
                if got_in_as:
                    row["why"].append(f"signed in as {got_in_as[0]}")
                earliest = min((x["first"] for x in r["signed_in"] if x["first"]), default="")
                if earliest and earliest < local(r["first"]):
                    row["why"].append("signed in before the failures started")
                signed_in.append(row)
            continue
        elif r["n"] >= SUSTAINED or r["attack_names"] >= 20:
            attackers.append(row)
        else:
            probes.append(row)
    attackers.sort(key=lambda x: -x["n"])
    signed_in.sort(key=lambda x: -x["n"])
    probes.sort(key=lambda x: (-len(x["servers"]), -x["n"]))

    # Who owns the addresses that matter: reverse DNS for all of them, RDAP for the busiest
    if lookups:
        named = [x["address"] for x in attackers + signed_in + probes][:LOOKUPS]
        sample = [ip for c in campaigns for ip in c["sample"][:40]]
        found = owners(named + sample, [x["address"] for x in attackers + signed_in][:15] + [x["address"] for x in probes][:5],
                       resolver, registry)
        for x in attackers + signed_in + probes:
            x["owner"] = found.get(x["address"], {})
        for c in campaigns:
            nets = collections.Counter(network(found.get(ip, {}).get("rdns", "")) or "(no name)" for ip in c["sample"][:40])
            c["networks"] = [[n, k] for n, k in nets.most_common(6)]
            c["looked_up"] = min(40, len(c["sample"]))
    for c in campaigns:
        c["all_addresses"] = c["sample"]      # every address, for a firewall's block list
        c["sample"] = c["sample"][:12]
    own = set()
    for s in servers:
        own |= host_words(s["host"], [])
        own |= {label.replace("-", "") for label in s["host"].lower().split(".") if len(label.replace("-", "")) > 3}
    block = block_list(signed_in, attackers, probes, frozenset(own))

    attack_ips = {x["address"] for x in attackers + signed_in + probes} | in_campaign
    table = []
    guest = []
    for s in servers:
        fails = {ip: f for ip, f in s["fails"].items() if ip in judged}
        outsiders_listed = [ip for ip, a in s["api"].items() if a["lists_ok"] and ip not in s["signins"]
                            and not any(a["ok_users"].values()) and public(ip)]
        table.append({"server": s["host"], "from": local(s["from"]), "to": local(s["to"]), "downloaded": downloaded(s["folder"]),
                      "failures": sum(f["n"] for f in fails.values()),
                      "attack_failures": sum(f["n"] for ip, f in fails.items() if ip in attack_ips),
                      "attackers": sum(1 for ip in fails if ip in attack_ips),
                      "file_list_to_outsiders": len(outsiders_listed),
                      "too_many": sum(a["too_many"] for a in s["api"].values()),
                      "doors": [[DOORS.get(d, d), n] for d, n in sum((collections.Counter(f["doors"]) for f in fails.values()),
                                                                      collections.Counter()).most_common()]})
        for ip, g in s["signins"].items():
            if g.get("guest") and public(ip):
                x = g["guest"]
                guest.append({"server": s["host"], "address": ip, "n": x["n"], "files": x["files"],
                              "webdirect": x["webdirect"], "first": local(x["first"]), "last": local(x["last"]),
                              "verified": ip in verified_addresses})
    table.sort(key=lambda x: -x["attack_failures"])

    # Each address's label, for the per-server lists and the failed-then-signed-in accounts
    label = {}
    for x in signed_in:
        label[x["address"]] = "attacked, then signed in"
    for x in attackers:
        label[x["address"]] = "sustained attack"
    for x in probes:
        label[x["address"]] = "probe"
    for ip in in_campaign:
        label[ip] = "campaign"
    for s in servers:
        rows = []
        for ip, f in s["fails"].items():
            if f["n"] < 2 or not public(ip):
                continue
            verified = ip in verified_addresses or (f["computers"] and all(c.lower() in verified_computers for c in f["computers"]))
            g = s["signins"].get(ip)
            rows.append({"address": ip, "n": f["n"], "account_names": len(f["accts"]),
                         "top_names": [[hide_typed_password(a) if a else "(blank)", k] for a, k in
                                       collections.Counter(f["accts"]).most_common(4)],
                         "first": local(f["first"]), "last": local(f["last"]), "signed_in": bool(g),
                         "label": "verified" if verified else label.get(ip, "")})
        rows.sort(key=lambda x: -x["n"])
        t = next(x for x in table if x["server"] == s["host"])
        t["addresses"], t["addresses_more"] = rows[:PER_SERVER], max(0, len(rows) - PER_SERVER)
        t["addresses_total"] = len(rows)

    # Accounts that failed several times, then signed in. Rated by where the failures and the sign-in came from
    runs = []
    for s in servers:
        for run in s.get("runs", []):
            ip = run["signed_in_from"]
            if all(not public(a) for a in run["addresses"]):
                continue    # the server's own scripts or an office network, not the internet
            g = s["signins"].get(ip, {})
            new = bool(g) and g.get("first", "") >= run["first"]
            attackers_failing = [a for a in run["addresses"] if label.get(a) and label.get(a) != "verified"]
            elsewhere = [a for a in run["addresses"] if a != ip]
            if label.get(ip) or (attackers_failing and new):
                risk, why = "High", ("signed in from an attacking address" if label.get(ip) else
                                     "attacking addresses failed on it, then it signed in from an address new to this server")
            elif attackers_failing:
                risk, why = "Medium", ("attacking addresses failed on it, then it signed in from an address that has signed "
                                       "in here before: most likely the account's own user, but the password is being guessed")
            elif run.get("peak_hour", 0) >= 10 or len(run["addresses"]) >= 3 or (elsewhere and new):
                risk, why = "Medium", (f"{run['peak_hour']} attempts in an hour, as guessing does" if run.get("peak_hour", 0) >= 10 else
                                       "failures from several addresses" if len(run["addresses"]) >= 3 else
                                       "signed in from an address new to this server, after failures from another")
            elif run["attempts"] >= 10:
                risk, why = "Low", "many attempts, spread out: most likely a device or integration with an old saved password"
            else:
                risk, why = "Low", "failed from the address it then signed in from: most likely a mistyped password"
            runs.append({"server": s["host"], "account": hide_typed_password(run["account"]), "attempts": run["attempts"],
                         "failures": run["failures"], "addresses": [[a, k, label.get(a, "")] for a, k in
                                                                    sorted(run["addresses"].items(), key=lambda x: -x[1])[:6]],
                         "first": local(run["first"]), "signed_in": local(run["signed_in"]), "from": ip,
                         "peak_hour": run.get("peak_hour", 0),
                         "from_label": label.get(ip, ""), "new_address": new, "risk": risk, "why": why})
    order = {"High": 0, "Medium": 1, "Low": 2}
    runs.sort(key=lambda x: (order[x["risk"]], -x["attempts"]))
    total = sum(r["n"] for r, _, _ in judged.values())
    attack_times = [(judged[ip][0]["first"], judged[ip][0]["last"], ip) for ip in attack_ips if ip in judged]
    gots = sorted((downloaded(s["folder"]), s["host"]) for s in servers)
    spans = [(s["from"], s["to"]) for s in servers if s["from"]]
    return {"generated": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
            "timezone": datetime.datetime.now().astimezone().strftime("%Z, UTC%z"),
            "servers_read": len(servers), "folders_read": read,
            "from": local(min(a for a, _ in spans)) if spans else "", "to": local(max(b for _, b in spans)) if spans else "",
            "summary": {"failures": total, "addresses": len(judged),
                        "attack_failures": sum(judged[ip][0]["n"] for ip in attack_ips if ip in judged),
                        "attackers": len(attackers), "signed_in": len(signed_in), "probes": len(probes),
                        "campaigns": len(campaigns), "campaign_addresses": len(in_campaign),
                        "servers_hit": sum(1 for t in table if t["attack_failures"]),
                        "servers_listing_files": sum(1 for t in table if t["file_list_to_outsiders"]),
                        "guest": len(guest), "left_out": dict(left_out),
                        "failed_then_signed_in": {k: sum(1 for r in runs if r["risk"] == k) for k in ("High", "Medium", "Low")},
                        "attacks_from": local(min(a for a, _, _ in attack_times)) if attack_times else "",
                        "attacks_from_address": min(attack_times)[2] if attack_times else "",
                        "attacks_to": local(max(b for _, b, _ in attack_times)) if attack_times else "",
                        "attacks_to_address": max(attack_times, key=lambda x: x[1])[2] if attack_times else "",
                        "downloaded_newest": gots[-1][0] if gots else "", "downloaded_oldest": gots[0][0] if gots else "",
                        "downloaded_oldest_server": gots[0][1] if gots else ""},
            "hosts": [s["host"] for s in servers],
            "failed_then_signed_in": [r for r in runs if r["risk"] != "Low"] + [r for r in runs if r["risk"] == "Low"][:40],
            "signed_in": signed_in, "attackers": attackers, "campaigns": campaigns, "probes": probes[:60],
            "probes_more": max(0, len(probes) - 60), "guest": guest, "servers": table, "block": block}


LOG_NAMES = ("Event.log", "Event-old.log", "Access.log", "Access-old.log", "fmdapi.log", "fmdapi-old.log",
             "fmodata.log", "fmodata-old.log")
SHOWN = 10      # rows of each list in the printed summary; everything is in the --out file


def stage(logs, work):
    """The skill's --logs folder as the sweep reads it: one folder per server under work, a .zip extracted there
    (log files only, by name, so nothing in the zip can write outside it). The source is never changed."""
    logs = os.path.expanduser(logs)
    if not os.path.isdir(logs):
        sys.exit(f"--logs must be a folder holding one folder or .zip per server: {logs} isn't a folder")
    for name in sorted(os.listdir(logs)):
        src = os.path.join(logs, name)
        if name.startswith("."):
            continue
        if os.path.isdir(src):
            # Copied, not linked: glob leaves symlinked folders out on some Python versions
            dest = os.path.join(work, name)
            os.makedirs(dest, exist_ok=True)
            for root, _, files in os.walk(src):
                for base in files:
                    if base in LOG_NAMES and not os.path.exists(os.path.join(dest, base)):
                        shutil.copyfile(os.path.join(root, base), os.path.join(dest, base))
        elif name.lower().endswith(".zip"):
            dest = os.path.join(work, name[:-4])
            os.makedirs(dest, exist_ok=True)
            with zipfile.ZipFile(src) as z:
                for m in z.infolist():
                    base = os.path.basename(m.filename)
                    if base in LOG_NAMES and not m.is_dir():
                        with z.open(m) as fsrc, open(os.path.join(dest, base), "wb") as fdst:
                            fdst.write(fsrc.read())
    if not os.listdir(work):
        sys.exit(f"No server folders or .zip files in {logs}: put each server's logs in a folder or .zip named for it")


def brief(r, out):
    """What an Agent reads: the verdict lines and the first SHOWN of each list. The rest stays in the --out file."""
    s, lines = r["summary"], []
    add = lines.append
    add(f"##### FMS global log review: {r['servers_read']} servers, logs {r['from']} to {r['to']} (this machine's time)")
    add(f"Failed sign-ins: {s['failures']:,}; {s['attack_failures']:,} look like attacks, from {s['attackers'] + s['signed_in'] + s['probes'] + s['campaign_addresses']:,} addresses")
    left = s.get("left_out", {})
    if left:
        add("Left out: " + ", ".join(f"{n:,} from {k} addresses" for k, n in left.items()))

    def servers(x):
        return ", ".join(f"{h} ({n})" for h, n in x["servers"][:4]) + (f" +{len(x['servers']) - 4} more" if len(x["servers"]) > 4 else "")
    add(f"\n## Attacked, then signed in: {len(r['signed_in'])}  (possible compromise: confirm who each is first)")
    for x in r["signed_in"][:SHOWN]:
        got = "; ".join(f"{g['server']} as {', '.join(g['accounts'][:2])}" + (f" from {g['first']}" if g["first"] else "") for g in x["signed_in"][:3])
        add(f"  {x['address']:40} n={x['n']:<6} {servers(x)} | {', '.join(x['why'])} | signed in: {got}")
    add(f"\n## Sustained attacks: {len(r['attackers'])}")
    for x in r["attackers"][:SHOWN]:
        add(f"  {x['address']:40} n={x['n']:<6} {servers(x)} | {', '.join(x['why'])} | {x['first']}..{x['last']}")
    add(f"\n## Rotating-address campaigns: {len(r['campaigns'])}")
    for c in r["campaigns"][:SHOWN]:
        add(f"  {c['from']}..{c['to']}: {c['addresses']} addresses, {c['tries']} tries, servers "
            + ", ".join(h for h, _ in c["servers"][:4]) + "; names " + ", ".join(a for a, _ in c["names"][:6]))
    add(f"\n## Smaller probes: {s['probes']}")
    for x in r["probes"][:SHOWN]:
        add(f"  {x['address']:40} n={x['n']:<6} {servers(x)} | {', '.join(x['why'])}")
    worth = [x for x in r["failed_then_signed_in"] if x["risk"] != "Low"]
    add(f"\n## Accounts that failed, then signed in: {len(worth)} worth a look (high {s['failed_then_signed_in']['High']}, "
        f"medium {s['failed_then_signed_in']['Medium']}), {s['failed_then_signed_in']['Low']} low")
    for x in worth[:SHOWN]:
        add(f"  {x['risk']:6} {x['server']}: {x['account']}, {x['attempts']} attempts, signed in {x['signed_in']} from {x['from']} | {x['why']}")
    add(f"\n## Guest sign-ins: {len(r['guest'])}")
    for g in r["guest"][:SHOWN]:
        add(f"  {g['server']}: {g['address']} {'WebDirect' if g['webdirect'] else 'FileMaker'} {', '.join(g['files'][:3])}")
    lists = [t for t in r["servers"] if t["file_list_to_outsiders"]]
    add(f"\n## Servers that gave their file list to addresses that never signed in: {len(lists)}")
    for t in lists[:SHOWN]:
        add(f"  {t['server']}: {t['file_list_to_outsiders']} addresses")
    now = [b for b in r["block"] if b["priority"] == "Block now"]
    add(f"\n## Block list: {len(now)} block now, {sum(1 for b in r['block'] if b['priority'] == 'Block if you can')} block if you can")
    for b in now[:SHOWN * 2]:
        add(f"  {b['address']:40} {b['why']}")
    add(f"\nEverything, with every address and server: {out}")
    return "\n".join(lines)


def main():
    args = sys.argv[1:]
    if "--logs" in args:
        cli(args)
        return
    job = {}
    if args and os.path.exists(args[0]):
        with open(args[0], encoding="utf-8") as f:
            job = json.load(f)
        os.remove(args[0])
    out = args[1] if len(args) > 1 else os.path.join(HERE, "sweep-logs-result.json")
    try:
        result = sweep(job.get("logs", LOGS_ROOT), job.get("verified_addresses", []), job.get("verified_computers", []),
                       job.get("lookups", True), hosts=job.get("hosts") or None)
        result["ok"] = True
    except Exception as e:   # the page shows why, rather than waiting for a file that never comes
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    tmp = out + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    os.replace(tmp, out)
    print(json.dumps({"ok": result["ok"]}))


def cli(args):
    def opt(name, default=""):
        return args[args.index(name) + 1] if name in args[:-1] else default
    out = os.path.abspath(opt("--out", "global-review.json"))
    split = lambda v: [x.strip() for x in v.split(",") if x.strip()]
    with tempfile.TemporaryDirectory(prefix="fms_sweep_") as work:
        stage(opt("--logs"), work)
        r = sweep(work, split(opt("--verified-addresses")), split(opt("--verified-computers")), "--lookups" in args)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=1)
    print(brief(r, out))


if __name__ == "__main__":
    main()
