#!/usr/bin/env python3
"""FMS log check: what happened on a FileMaker Server since a given time.

Reads a folder of FileMaker Server logs (or the .zip they came in) and reports:
new addresses, failed sign-ins with warning flags, addresses that failed and
also signed in, Guest sign-ins, ODBC/JDBC connections, Admin Console sign-ins,
security and file events, Admin API errors, bursts of record downloads, what
each address did through the Data API and OData (fmdapi.log, fmodata.log: file
and layout lists, paging, Guest), and outside requests to FileMaker, PHP and XML
web paths. Uses only the Python standard library.

Usage:
    python3 fms_logcheck.py <log folder or .zip> [since] [--brief] [--save <file>]

    since   "YYYY-MM-DD HH:MM" in the server's local time. If left out, the
            check covers the 24 hours before the newest Access.log entry.
    --brief     the busiest and new connections, the failed sign-ins that matter most and
                counts for the rest, so an Agent reading it keeps its context small. On a
                server with 288 addresses, 81 KB of output became about 10 KB.
    --save      also write the full output to this file, to search when a line is needed.

Examples:
    python3 fms_logcheck.py server-logs.zip
    python3 fms_logcheck.py ./Logs "2026-10-28 01:00"

Read-only: it never changes the logs. A .zip is extracted to a temporary folder.
See references/log-review.md in the cadenceux-fms-security skill for what each
flag means and when to escalate.
"""
import collections
import datetime
import gzip
import ipaddress
import os
import re
import sys
import tempfile
import zipfile

# Account names attackers try first, on any server. From the attacks in Claris's lockdown guide and the names that
# failed on many of our own servers from addresses that never signed in: admin on 49 of 53, fmadmin on 32.
GENERIC = {"", "admin", "administrator", "adm", "root", "sa", "sysadmin", "superuser", "manager", "owner", "master",
           "support", "developer", "dev", "demo", "test", "testuser", "user", "guest", "[guest]", "web", "webuser",
           "website", "api", "apiuser", "dataapi", "fmrest", "fmodata", "odbc", "jdbc", "filemaker", "fm", "fmadmin",
           "fmsadmin", "fmserver", "fmuser"}
# The doors a failed sign-in can come through: the bracket in Event.log, and the Admin Console's own line
DOORS = {"fmapp": "FileMaker Pro/Go", "fmwebdirect": "WebDirect", "fmrest": "Data API", "fmodata": "OData",
         "fmxdbc": "ODBC/JDBC", "fmxml": "XML", "fmphp": "PHP", "admin-console": "Admin Console"}
MANY_DOORS = 3        # connection types one address fails through; staff use one or two (Pro and WebDirect)
IP = r"(\d+\.\d+\.\d+\.\d+|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})"
LOCAL = {"127.0.0.1", "::1"}
DOWNLOAD_MB = 20      # per client per 10 minutes; busy production servers peaked near 6 MB
WIDE_TABLES = 40      # developers reach 60+ tables, so WIDE needs a NEW or GUEST/GENERIC client too
FAIL_RATE = 20        # failures per address per 10 minutes; a person retrying rarely passes this on more than one name
API_CALLS = 100       # Data API / OData record calls per address per 10 minutes (attackers page 200 at a time)
API_LAYOUTS = 5       # layouts (or OData tables) one address reads records from: in 10 minutes for BURST, in all for MAPPED
API_PAGES = 20        # calls for a later page (_offset past 1, $skip past 0) per address per 10 minutes: PAGING
BRIEF_API = 15        # --brief: Data API and OData addresses shown, the most serious flags first
# Data API and OData flags, most serious first. NEW is shown but never raised on its own: cloud integrations
# (Power Automate, Zapier) call from a different address most days.
API_FLAGS = ["GUEST", "MAPPED", "BURST", "PAGING", "FILE-LIST", "GENERIC/DEFAULT"]
# Server-wide checks (Claris, "Lock Down Your FileMaker Server", section 5): attackers rotate addresses, one or two
# calls each, so per-address counts miss them. Alert on the whole server's hourly failure rate against its own normal.
SPIKE_FACTOR = 4      # an hour with 4x the median hourly failures (Claris suggests starting at 3 to 5 times)...
SPIKE_MIN = 10        # ...and at least this many, so a quiet server's single typo isn't a spike
FILE_ACCOUNTS = 6     # different account names failing on one file in one day, from any number of addresses
FILE_ADDRESSES = 6    # different addresses failing on one file in one day (staff mistyping rarely reach either)
BRIEF_BUSIEST = 10    # --brief: the busiest connections shown; NEW ones are always shown
BRIEF_FAILS = 25      # --brief: failed sign-in addresses shown, the most serious flags first
# The flags that make a failed sign-in address worth reading in --brief, most serious first. NEVER-SUCCEEDED and
# BEFORE-ACCESS-LOG are on almost every address that fails, so on their own they're only counted.
BRIEF_FLAGS = ["POSSIBLE-COMPROMISE", "SIGNED-IN", "XDBC", "RATE", "MANY-ACCOUNTS", "MANY-FILES", "MANY-DOORS", "GENERIC/DEFAULT",
               "SERVER-ITSELF"]

FULL, OPTS = [], {"brief": False}


def out(text="", brief=True):
    """Every line goes to the full output (--save); a line marked brief=False is left out of --brief."""
    FULL.append(text)
    if brief or not OPTS["brief"]:
        print(text)


def is_log(name):
    """A .log file, or a rotated web-server log (nginx-access.log-YYYY-MM-DD, perhaps gzipped)."""
    return name.endswith(".log") or re.fullmatch(r"nginx-access\.log-[\d-]+(\.gz)?", name) is not None


def open_logs(path):
    """Return a dict of log file name -> full path, extracting a .zip first."""
    path = os.path.expanduser(path)
    if path.lower().endswith(".zip"):
        out = tempfile.mkdtemp(prefix="fms_logcheck_")
        with zipfile.ZipFile(path) as z:
            for m in z.infolist():
                name = os.path.basename(m.filename)
                if is_log(name) and not m.is_dir():
                    with z.open(m) as src, open(os.path.join(out, name), "wb") as dst:
                        dst.write(src.read())
        path = out
    found = {}
    for root, _, files in os.walk(path):
        for f in files:
            if is_log(f):
                found.setdefault(f, os.path.join(root, f))
    return found


def lines(logs, *names):
    for n in names:
        if n in logs:
            opener = gzip.open if n.endswith(".gz") else open
            with opener(logs[n], "rt", encoding="utf-8-sig", errors="replace") as f:
                for l in f:
                    yield l.rstrip("\n")


def fms_advisories_vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def ip_of(text):
    m = re.search(r"[\[(]" + IP + r"[\])]", text)
    return m.group(1) if m else None


def hide_typed_password(name):
    """People type passwords into the account box. Don't copy one into a report."""
    if re.search(r"[^\w .@'-]", name) or (len(name) >= 8 and re.search(r"[a-z]", name)
                                          and re.search(r"[A-Z]", name) and re.search(r"\d", name)):
        return "<hidden: may be a typed password>"
    return name


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        sys.exit(__doc__)
    OPTS["brief"] = "--brief" in args
    save = args[args.index("--save") + 1] if "--save" in args[:-1] else ""
    args = [a for i, a in enumerate(args) if a != "--brief" and a != "--save" and not (i and args[i - 1] == "--save")]
    try:
        report(args, save)
    finally:
        if save:
            with open(save, "w", encoding="utf-8") as f:
                f.write("\n".join(FULL) + "\n")


def server_wide(hourly, by_file, span):
    """The whole server's failed sign-ins per hour against its own median hour, and files that many accounts or
    addresses fail on. Catches spraying spread across rotating addresses, which the per-address flags miss."""
    hours = []
    if span:
        t = datetime.datetime.strptime(span[0], "%Y-%m-%d %H")
        end = datetime.datetime.strptime(span[1], "%Y-%m-%d %H")
        while t <= end and len(hours) < 24 * 400:
            hours.append(t.strftime("%Y-%m-%d %H"))
            t += datetime.timedelta(hours=1)
    counts = sorted(hourly[h]["n"] if h in hourly else 0 for h in hours)
    median = counts[len(counts) // 2] if counts else 0
    limit = max(SPIKE_MIN, SPIKE_FACTOR * median)
    spikes = [h for h in hours if h in hourly and hourly[h]["n"] >= limit]
    total = sum(r["n"] for r in hourly.values())
    out(f"\n## Server-wide failed sign-ins: {total} over {len(hours)} hours, median {median} an hour, "
        f"{len(spikes)} spike hour(s) at {limit}+")
    out(f"   Flags: SPIKE ({SPIKE_FACTOR}x the median hour, at least {SPIKE_MIN}), SPREAD (most of that hour's addresses "
        f"failed only once or twice: rotating addresses), FILE-TARGETED ({FILE_ACCOUNTS}+ accounts or "
        f"{FILE_ADDRESSES}+ addresses failing on one file in a day). The server's own 127.0.0.1 is left out")
    for h in spikes[:24]:
        r = hourly[h]
        few = sum(1 for n in r["ips"].values() if n <= 2)
        spread = len(r["ips"]) >= 5 and few >= len(r["ips"]) * 0.6
        out(f"  {h}:00  n={r['n']:<5} addresses={len(r['ips']):<4} accts={len(r['acct']):<4} SPIKE"
            + (f" SPREAD ({few} addresses with 1-2 failures)" if spread else ""))
    if len(spikes) > 24:
        out(f"  and {len(spikes) - 24} more spike hours")
    # By file and day: each file's worst day, and how many days were over the line
    worst, days = {}, collections.Counter()
    for (name, day), f in by_file.items():
        if len(f["acct"]) >= FILE_ACCOUNTS or len(f["ips"]) >= FILE_ADDRESSES:
            days[name] += 1
            if name not in worst or (len(f["acct"]), len(f["ips"])) > (len(worst[name][1]["acct"]), len(worst[name][1]["ips"])):
                worst[name] = (day, f)
    targeted = sorted(worst.items(), key=lambda x: -(len(x[1][1]["acct"]) + len(x[1][1]["ips"])))
    for name, (day, f) in targeted:
        out(f"  {name:40} n={f['n']:<5} addresses={len(f['ips']):<4} accts={len(f['acct']):<4} FILE-TARGETED "
            f"(worst day {day}, {days[name]} day(s) over the line)")
    if not spikes and not targeted:
        out("   No spike and no file targeted across addresses in this window")

# Data API and OData request logs. OttoFMS downloads them where the web server's own log isn't available, and they
# hold what the Claris pattern needs: the file list, then the layouts, then page after page of records from each.
API_FILE_LIST = re.compile(r"^/fmi/(?:data/[^/]+/databases|odata/v\d+)/?$")
API_LAYOUT_LIST = re.compile(r"^/fmi/(?:data/[^/]+/databases/[^/]+/layouts|odata/v\d+/[^/$]+(?:/\$metadata)?)/?$")
API_RECORDS = re.compile(r"^/fmi/(?:data/[^/]+/databases/([^/]+)/layouts/([^/]+)/(?:records|_find)|odata/v\d+/([^/$]+)/([^/$(]+))")


def api_time(stamp, offset):
    """fmdapi.log writes local time ("2026-11-03 10:00:00.000 +1100"); fmodata.log writes UTC ("2026-11-02T23:00:00Z").
    Both are compared with the window in the server's local time."""
    if "T" not in stamp[:11]:
        return stamp[:16]
    try:
        t = datetime.datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return ""
    sign = -1 if offset[:1] == "-" else 1
    return (t + sign * datetime.timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))).strftime("%Y-%m-%d %H:%M")


def api_requests(logs, since, is_new, seen_before):
    names = [n for n in ("fmdapi-old.log", "fmdapi.log", "fmodata-old.log", "fmodata.log") if n in logs]
    if not names:
        out("\n## Data API and OData requests (fmdapi.log, fmodata.log): not supplied")
        return
    offset = "+0000"
    for l in lines(logs, "Event.log", "fmdapi.log"):
        m = re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\S* ([+-]\d{4})\t", l)
        if m:
            offset = m.group(1)
            break
    addr = collections.defaultdict(lambda: dict(n=0, ok=0, failed=0, records=0, layouts=set(), paged=0, files=0, files_ok=0, lists=0, refused=0,
                                                users=set(), first="", last="", win=collections.Counter(),
                                                win_layouts=collections.defaultdict(set), win_paged=collections.Counter()))
    total = 0
    for name in names:
        for l in lines(logs, name):
            f = l.split("\t")
            if len(f) < 7 or not f[0][:4].isdigit():
                continue
            ts = api_time(f[0], offset)
            ip, user, method, path = f[3], f[4].strip(), f[5].upper(), f[6]
            if not ts or not ip:
                continue
            if ts < since:
                seen_before.add(ip)
                continue
            total += 1
            bare = path.split("?")[0]
            r = addr[ip]
            r["n"] += 1
            r["first"] = r["first"] or ts
            r["last"] = max(r["last"], ts)
            ok = f[1].strip() == "0"
            r["ok" if ok else "failed"] += 1
            if ok and user:
                r["users"].add(user)
            if method == "GET" and API_FILE_LIST.match(bare):
                r["files"] += 1
                r["files_ok"] += ok
            elif method == "POST" and bare.endswith("/sessions") and not ok:
                r["refused"] += 1
            elif method == "GET" and API_LAYOUT_LIST.match(bare):
                r["lists"] += 1
            m = API_RECORDS.match(bare)
            if m and ok and ((m.group(2) and (method == "GET" or bare.endswith("/_find"))) or (m.group(4) and method == "GET")):
                where = "/".join(x for x in m.groups() if x)
                win = ts[:15] + "0"
                r["records"] += 1
                r["layouts"].add(where)
                r["win"][win] += 1
                r["win_layouts"][win].add(where)
                page = re.search(r"[?&](?:_offset|\$skip)=(\d+)", path)
                if page and int(page.group(1)) > (1 if "_offset" in page.group(0) else 0):
                    r["paged"] += 1
                    r["win_paged"][win] += 1
    rows = []
    for ip, r in addr.items():
        users = {u.lower() for u in r["users"]}
        peak = max(r["win"].values(), default=0)
        wide = max((len(v) for v in r["win_layouts"].values()), default=0)
        flags = []
        if users & {"[guest]", "guest"}:
            flags.append("GUEST")
        if r["lists"] and len(r["layouts"]) >= API_LAYOUTS:
            flags.append("MAPPED")
        if peak >= API_CALLS or wide >= API_LAYOUTS:
            flags.append("BURST")
        if max(r["win_paged"].values(), default=0) >= API_PAGES:
            flags.append("PAGING")
        if r["files"] and not users:
            flags.append("FILE-LIST")
        if users & (GENERIC - {"", "guest", "[guest]"}):
            flags.append("GENERIC/DEFAULT")
        if is_new(ip):
            flags.append("NEW")
        rows.append((ip, r, peak, wide, flags))
    # Addresses whose only flag is FILE-LIST are one line: internet-wide sweeps list the files from dozens of addresses
    listers = [x for x in rows if set(x[4]) & set(API_FLAGS) == {"FILE-LIST"}]
    flagged = [x for x in rows if set(x[4]) & set(API_FLAGS) - {"FILE-LIST"}]
    out(f"\n## Data API and OData requests ({', '.join(names)}): {total} requests from {len(addr)} addresses, "
        f"{len(flagged)} flagged")
    out(f"   Flags: GUEST (signed in as Guest), MAPPED (listed the layouts or tables, then read records from "
        f"{API_LAYOUTS}+ of them),\n   BURST ({API_CALLS}+ record calls or {API_LAYOUTS}+ layouts in 10 minutes), PAGING "
        f"({API_PAGES}+ later pages in 10 minutes),\n   FILE-LIST (asked for the list of hosted files and never signed in), "
        f"GENERIC/DEFAULT account, NEW. Record calls count only when answered")
    def weight(x):
        return min((API_FLAGS.index(f) for f in x[4] if f in API_FLAGS), default=len(API_FLAGS))
    flagged.sort(key=lambda x: (weight(x), -x[1]["records"], -x[1]["n"]))
    for rank, (ip, r, peak, wide, flags) in enumerate(flagged):
        users = sorted(hide_typed_password(u) for u in r["users"])
        out(f"  {ip:40} calls={r['n']:<6} records={r['records']:<6} layouts={len(r['layouts']):<3} peak10={peak:<5} "
            f"paged={r['paged']:<6} filelist={r['files']:<4} layoutlist={r['lists']:<4} failed={r['failed']:<5} "
            f"users={users[:4]} {r['first']}..{r['last'][5:]} {' '.join(flags)}", brief=rank < BRIEF_API)
    if OPTS["brief"] and len(flagged) > BRIEF_API:
        print(f"   and {len(flagged) - BRIEF_API} more flagged addresses (all in the full output)")
    if listers:
        listers.sort(key=lambda x: -x[1]["n"])
        answered = sum(1 for x in listers if x[1]["files_ok"])
        tried = sum(1 for x in listers if x[1]["refused"])
        out(f"  FILE-LIST {len(listers)} addresses asked for the list of hosted files and never signed in, "
            f"{min(x[1]['first'] for x in listers)}..{max(x[1]['last'] for x in listers)[5:]}: the list was answered for "
            f"{answered}, and {tried} then failed to sign in. The busiest: "
            + ", ".join(f"{ip} ({r['files']} list{'s' * (r['files'] != 1)}, {r['refused']} failed sign-in"
                        f"{'s' * (r['refused'] != 1)})" for ip, r, *_ in listers[:5]))
    if not flagged and not listers:
        out("   Nothing flagged")
    shown = {id(x) for x in flagged + listers}
    quiet = sorted((x for x in rows if id(x) not in shown), key=lambda x: -x[1]["n"])
    if quiet:
        out(f"   Not flagged: {len(quiet)} addresses, the busiest "
            + ", ".join(f"{ip} ({r['n']} calls, {len(r['layouts'])} layouts)" for ip, r, *_ in quiet[:5]), brief=False)


def report(args, save):
    logs = open_logs(args[0])
    if "Access.log" not in logs or "Event.log" not in logs:
        sys.exit("Access.log and Event.log are needed; found: " + ", ".join(sorted(logs)))
    if len(args) > 1:
        since = args[1]
    else:
        last = max(l[:16] for l in lines(logs, "Access.log") if l[:4].isdigit())
        since = (datetime.datetime.strptime(last, "%Y-%m-%d %H:%M") - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")

    # Access log: who connected, and which addresses are new
    seen_before = set()
    after = collections.defaultdict(lambda: dict(n=0, pc=set(), app=set(), acct=set(), first=None, last=None))
    signins = collections.defaultdict(list)   # address -> (time, account, connection type), at any date
    xdbc = collections.defaultdict(lambda: dict(n=0, acct=set(), first=None, last=None))
    via, access_first = {}, None
    guests = collections.defaultdict(lambda: dict(n=0, files=set(), via=set(), first=None, last=None))
    for l in lines(logs, "Access-old.log", "Access.log"):
        ts, ip = l[:16], ip_of(l)
        if not ip or not ts[:4].isdigit():
            continue
        access_first = access_first or ts
        m = re.search(r'opening a connection from .*using "([^"]+)"', l)
        if m:
            via[ip] = m.group(1)
            if ts >= since and re.search(r"JDBC|ODBC|fmxdbc", m.group(1), re.I):
                x = xdbc[ip]
                x["n"] += 1
                x["first"] = x["first"] or ts
                x["last"] = ts
                c = re.search(r'Client "([^"]*)"', l)
                if c:
                    x["acct"].add(c.group(1))
        m = re.search(r'opening database .* as "([^"]*)"', l)
        if m:
            signins[ip].append((ts, m.group(1), via.get(ip, "")))
            g = re.search(r'opening database "([^"]*)" as "\[Guest\]"', l)
            if g and ts >= since:
                r = guests[ip]
                r["n"] += 1
                r["first"] = r["first"] or ts
                r["last"] = ts
                r["files"].add(g.group(1))
                r["via"].add((re.findall(r"\[(\w+)\]", via.get(ip, "")) or ["?"])[-1])
        if ts < since:
            seen_before.add(ip)
            continue
        r = after[ip]
        r["n"] += 1
        r["first"] = r["first"] or ts
        r["last"] = ts
        for key, pat in (("pc", r'from "(.*) \(' + IP + r'\)"'), ("app", r'using "([^"]+)"'), ("acct", r'as "([^"]*)"')):
            m = re.search(pat, l)
            if m:
                r[key].add(m.group(1).split("@")[0])

    # Event log: addresses seen before the window also count as known
    for l in lines(logs, "Event-old.log", "Event.log"):
        if l[:16] < since and l[:4].isdigit():
            ip = ip_of(l)
            if ip and ("connected" in l or "opening" in l):
                seen_before.add(ip)

    # A window that starts at or before the first log entry has nothing to compare with
    first_review = not seen_before

    def is_new(ip):
        return not first_review and ip not in seen_before and ip not in LOCAL

    out(f"##### FMS log check: {since} onward")
    out(f"Files: {', '.join(sorted(logs))}")
    out(f"\n## Connections (Access.log): {len(after)} addresses, {sum(r['n'] for r in after.values())} lines")
    if first_review:
        out("   First review: the window starts at the first log entry, so no address can be marked NEW")
    else:
        out("   NEW = address not seen before the window")
    private = [ip for ip in after if ipaddress.ip_address(ip).is_private]
    if after and len(private) == len(after):
        out("   All addresses are private: the server is behind NAT, a proxy, a load balancer or a container\n"
              "   gateway, so these logs don't show real client addresses. Check the edge firewall or proxy logs")
    for rank, (ip, r) in enumerate(sorted(after.items(), key=lambda x: -x[1]["n"])):
        flag = "NEW " if is_new(ip) else "    "
        out(f"{flag}{ip:40} n={r['n']:<6} {r['first']}..{r['last'][5:]} pc={sorted(r['pc'])[:3]} "
            f"app={sorted(r['app'])[:2]} acct={sorted(r['acct'])[:5]}", brief=rank < BRIEF_BUSIEST or is_new(ip))
    hidden = sum(1 for rank, (ip, r) in enumerate(sorted(after.items(), key=lambda x: -x[1]["n"]))
                 if not (rank < BRIEF_BUSIEST or is_new(ip)))
    if OPTS["brief"] and hidden:
        print(f"   and {hidden} more addresses, none NEW (all in the full output)")

    fails = collections.defaultdict(lambda: dict(n=0, xdbc=0, acct=set(), files=set(), chan=set(), first=None,
                                                 windows=collections.Counter()))
    admin, admin_fail, other = collections.Counter(), collections.Counter(), collections.Counter()
    hourly = collections.defaultdict(lambda: dict(n=0, ips=collections.Counter(), acct=set()))   # all addresses but the server
    by_file = collections.defaultdict(lambda: dict(n=0, ips=set(), acct=set()))
    span = []                                                                                      # first and last Event hour
    for l in lines(logs, "Event-old.log", "Event.log"):
        if l[:16] < since or not l[:4].isdigit():
            continue
        span = [min(span[0], l[:13]), max(span[1], l[:13])] if span else [l[:13], l[:13]]
        msg = l.split("\t", 4)[-1]
        # A failed sign-in is judged the same whichever door it came through: FileMaker Pro or Go (5003), WebDirect,
        # the Data API, OData, XML or PHP (443), ODBC/JDBC (2399), or the Admin Console. Attacks try them all.
        fm = re.search(r'on database "([^"]+)" using "(?:([^"]*?) )?\[(\w+)\]"', msg) \
            if "authentication failed on database" in msg else None
        am = re.search(r'Administrator authentication failed: "(.*?) \[[^\]]+\]"', msg) \
            if "Administrator authentication failed" in msg else None
        if am:
            admin_fail[ip_of(msg)] += 1
        if fm or am or "authentication failed on database" in msg:
            fip = ip_of(msg) or "?"
            where, acct, door = (fm.group(1), fm.group(2) or "", fm.group(3).lower()) if fm else \
                ("(Admin Console)", am.group(1), "admin-console") if am else (None, None, None)
            if fip not in LOCAL:
                h = hourly[l[:13]]
                h["n"] += 1
                h["ips"][fip] += 1
                if where:
                    h["acct"].add(acct.lower())
                    f = by_file[(where, l[:10])]
                    f["n"] += 1
                    f["ips"].add(fip)
                    f["acct"].add(acct.lower())
            r = fails[fip]
            r["n"] += 1
            r["first"] = r["first"] or l[:16]
            r["windows"][l[:15]] += 1
            if where:
                if fm:
                    r["files"].add(where)
                r["acct"].add(acct)
                r["chan"].add(door)
                # fmxdbc is ODBC/JDBC on 2399, which a web rate limiter or WAF never sees
                if door == "fmxdbc":
                    r["xdbc"] += 1
        elif "Administrator connected" in msg:
            m = re.search(r'"(\S+) \[([^\]]+)\]" \(([^)]+)\)', msg)
            if m:
                admin[(m.group(2), m.group(1), m.group(3))] += 1
        elif re.search(r"SECURITY|upload|removed|Guest|Schedule .* (created|modified|deleted)|setting|changed", msg, re.I) \
                and "Secure (SSL)" not in msg:
            other[re.sub(r"\d", "#", msg)[:150]] += 1

    out(f"\n## Failed FileMaker sign-ins: {sum(r['n'] for r in fails.values())} from {len(fails)} addresses")
    out("   Every door is judged the same: " + ", ".join(f"{v} ({k})" for k, v in DOORS.items()))
    out(f"   Flags: POSSIBLE-COMPROMISE, SIGNED-IN, NEVER-SUCCEEDED, BEFORE-ACCESS-LOG, MANY-ACCOUNTS (3+), MANY-FILES (3+),\n"
        f"   MANY-DOORS ({MANY_DOORS}+ connection types),\n"
          f"   GENERIC/DEFAULT account, XDBC (ODBC/JDBC, port 2399), RATE ({FAIL_RATE}+ in 10 minutes), SERVER-ITSELF")
    xdbc_fails = {ip: r["xdbc"] for ip, r in fails.items() if r["xdbc"]}
    if xdbc_fails:
        out(f"   ODBC/JDBC: {sum(xdbc_fails.values())} of the failures came through port 2399, from {len(xdbc_fails)} address(es).\n"
              "   The attacks use 2399 too; unless a known SQL or BI tool explains them, close 2399 or allow-list it")
    typed, rows = False, []
    for ip, r in sorted(fails.items(), key=lambda x: -x[1]["n"]):
        flags, peak = [], max(r["windows"].values())
        ok = signins.get(ip, []) if ip not in LOCAL else []
        accts = {a.lower() for a in r["acct"]}
        if ip in LOCAL:
            flags.append("SERVER-ITSELF")
        if ok:
            # A success counts before or after the failures. Show the sign-in that matters most.
            risky = [s for s in ok if re.search(r"JDBC|ODBC|fmxdbc", s[2], re.I) or s[1].lower() in GENERIC]
            when, who, how = (risky or ok)[0]
            if risky or (is_new(ip) and len(r["acct"]) >= 3):
                flags.append("POSSIBLE-COMPROMISE")
            how = re.sub(r"\s*\[\w+\]$", "", how) or "?"
            flags.append(f"SIGNED-IN as {hide_typed_password(who)} {when} via {how} ({len(ok)} sign-ins)")
        elif ip not in seen_before and ip not in LOCAL:
            # Without Access.log for that date, a success can't be ruled out
            flags.append("BEFORE-ACCESS-LOG" if not access_first or r["first"] < access_first else "NEVER-SUCCEEDED")
        if len(r["acct"]) >= 3:
            flags.append("MANY-ACCOUNTS")
        if len(r["files"]) >= 3:
            flags.append("MANY-FILES")
        if len(r["chan"]) >= MANY_DOORS:
            flags.append("MANY-DOORS")
        if accts & GENERIC:
            flags.append("GENERIC/DEFAULT")
        if r["xdbc"]:
            flags.append("XDBC")
        if peak >= FAIL_RATE and ip not in LOCAL:
            flags.append("RATE")
        shown = [hide_typed_password(a) for a in sorted(r["acct"])]
        typed = typed or any(a.startswith("<hidden") for a in shown)
        more = f" +{len(shown) - 12} more" if len(shown) > 12 else ""
        rows.append((flags, f"  {ip:40} n={r['n']:<4} peak10={peak:<3} accts={len(shown)} {shown[:12]}{more} files={len(r['files'])} "
                            f"via={sorted(r['chan'])} {' '.join(flags)}"))
    # --brief: the most serious first (the first BRIEF_FLAGS flag each has), then the busiest; the rest as counts
    def weight(flags):
        names = [f.split(" ")[0] for f in flags]
        return min((BRIEF_FLAGS.index(f) for f in names if f in BRIEF_FLAGS), default=len(BRIEF_FLAGS))
    keep = {id(x) for x in sorted(rows, key=lambda x: weight(x[0]))[:BRIEF_FAILS] if weight(x[0]) < len(BRIEF_FLAGS)}
    for x in rows:
        out(x[1], brief=id(x) in keep)
    if OPTS["brief"] and len(rows) > len(keep):
        counts = collections.Counter(f.split(" ")[0] for x in rows if id(x) not in keep for f in x[0])
        print(f"   and {len(rows) - len(keep)} more addresses (all in the full output), flagged: "
              + (", ".join(f"{k} {n}" for k, n in counts.most_common()) or "nothing"))
    if typed:
        out("   An account name above looks like a typed password. It's hidden here and stays in the log:\n"
              "   have the person change that password, and don't copy that log line into a report")
    if not access_first:
        out("   Access.log has no dated lines, so no address can be said to have never signed in")

    server_wide(hourly, by_file, span)

    # Guest needs no password, so a Guest sign-in never shows as a failure. Through an API or WebDirect it is
    # a sign-in from anywhere (Claris, "Lock Down Your FileMaker Server", Appendix B: any Guest sign-in through an API)
    out(f"\n## Guest sign-ins (Access.log): {sum(r['n'] for r in guests.values())} from {len(guests)} addresses")
    if guests:
        out("   Flags: GUEST, API (through the Data API, OData, XML or PHP), WEBDIRECT, NEW. Guest should be off in every file")
    for ip, r in sorted(guests.items(), key=lambda x: -x[1]["n"]):
        flags = ["GUEST"] + (["API"] if r["via"] & {"fmrest", "fmodata", "fmxml", "fmphp"} else []) \
            + (["WEBDIRECT"] if "fmwebdirect" in r["via"] else []) + (["NEW"] if is_new(ip) else [])
        out(f"  {ip:40} n={r['n']:<5} {r['first']}..{r['last'][5:]} files={sorted(r['files'])[:6]} via={sorted(r['via'])} "
            + " ".join(flags))

    out(f"\n## ODBC/JDBC connections (Access.log): {sum(x['n'] for x in xdbc.values())} from {len(xdbc)} addresses")
    for ip, x in sorted(xdbc.items(), key=lambda i: -i[1]["n"]):
        flag = ("  NEW" if is_new(ip) else "") + ("  GENERIC" if {a.lower() for a in x["acct"]} & GENERIC else "")
        out(f"  {ip:40} n={x['n']:<5} {x['first']}..{x['last'][5:]} accts={sorted(x['acct'])[:8]}{flag}")

    # Client versions: which FileMaker Pro and Go builds connected, matched against the
    # skill's bundled FileMaker Pro advisories (no network; fms_advisories.py has the live list)
    clients = collections.defaultdict(lambda: dict(n=0, where=set()))
    for ip, r in after.items():
        for app in r["app"]:
            m = re.match(r"(Pro\w*|Go\w*)\s+(\d+(?:\.\d+){1,3})", app)
            if m:
                c = clients[(m.group(1), m.group(2))]
                c["n"] += 1
                c["where"].update(sorted(r["pc"])[:2] or [ip])
    if clients:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import fms_advisories
            adv = fms_advisories.load_bundled()
        except (ImportError, SystemExit):
            adv = None
        out(f"\n## Client versions (Access.log): {len(clients)} FileMaker Pro/Go build(s)")
        for (kind, ver), c in sorted(clients.items(), key=lambda x: fms_advisories_vt(x[0][1])):
            note = ""
            if adv and kind.startswith("Pro"):
                hits = [(e, fms_advisories.affects(e, ver, "pro")) for e in adv["cves"]]
                hits = [f"{e['id']} (fixed {f}{', ' + e['platform'] + ' only' if e.get('platform') else ''})"
                        for e, f in hits if f]
                if hits:
                    note = "  UPDATE: " + "; ".join(hits)
            out(f"  {kind + ' ' + ver:24} {c['n']:3} address(es), e.g. {', '.join(sorted(c['where'])[:3])}{note}")

    out("\n## Admin Console / fmsadmin sign-ins")
    for rank, ((ip, acct, how), n) in enumerate(admin.most_common()):
        flags = ("  NEW" if is_new(ip) else "") + ("  GENERIC" if acct.lower() in GENERIC else "")
        out(f"  {n:4} {ip:40} {acct} ({how}){flags}", brief=rank < 15)
    if OPTS["brief"] and len(admin) > 15:
        rest = list(admin)[15:]
        print(f"   and {len(rest)} more address and account pairs (all in the full output): "
              f"{sum(1 for ip, a, h in rest if is_new(ip))} NEW, {sum(1 for ip, a, h in rest if a.lower() in GENERIC)} GENERIC")
    out(f"## Admin sign-in failures: {dict(admin_fail) or 'none'}")

    out("\n## Security, settings and file events")
    for rank, (k, n) in enumerate(other.most_common(30)):
        out(f"  {n:4} {k}", brief=rank < 10)

    fac = [l for l in lines(logs, "fac.log") if l[:16] >= since and re.search(r"error", l, re.I) and "Data Storage" not in l]
    out(f"\n## Admin API errors (fac.log): {len(fac)}")
    for k, n in collections.Counter(re.sub(r"^\S+ \S+ \S+", "", re.sub(r"\d", "#", l))[:140] for l in fac).most_common(10):
        out(f"  {n:4} {k}")

    # Record downloads: per client, per 10-minute window. TopCallStats keeps only the
    # busiest calls in each interval, so these counts are a floor, not a total.
    reads = collections.defaultdict(lambda: dict(n=0, mb=0.0, tables=set()))
    for p in (l.split("\t") for l in lines(logs, "TopCallStats-old.log", "TopCallStats.log")):
        if len(p) < 12 or p[0][:16] < since or not p[0][:4].isdigit() or not re.match(r"Query|Download", p[4]):
            continue
        if "(FileMaker Script)" in p[11]:
            continue
        r = reads[(re.sub(r"@\S+", "", p[11]).strip(), p[0][:15] + "0")]
        r["n"] += 1
        r["mb"] += int(p[7] or 0) / 1e6
        r["tables"].add("::".join(p[5].split("::")[:2]))
    if "TopCallStats.log" not in logs:
        out("\n## Record downloads (TopCallStats.log): not supplied")
    else:
        out(f"\n## Record downloads (TopCallStats.log): {len(reads)} client 10-minute windows")
        out(f"   Flags: HIGH-VOLUME ({DOWNLOAD_MB}+ MB), WIDE ({WIDE_TABLES}+ tables) on a NEW address "
              "or GUEST/GENERIC account")
        # The 5 biggest windows by volume, then the 5 widest, without repeats
        shown = dict(sorted(reads.items(), key=lambda x: -x[1]["mb"])[:5] +
                     sorted(reads.items(), key=lambda x: -len(x[1]["tables"]))[:5])
        for (who, win), r in shown.items():
            ip = (re.findall(r"\[([^\]]+)\]", who) or ["?"])[-1]
            accts = {a.lower() for a in after.get(ip, {}).get("acct", ())} | {who.split(" ")[0].lower()}
            flags = []
            if r["mb"] >= DOWNLOAD_MB:
                flags.append("HIGH-VOLUME")
            risky = is_new(ip) or accts & GENERIC
            if len(r["tables"]) >= WIDE_TABLES and risky:
                flags.append("WIDE")
            if is_new(ip):
                flags.append("NEW")
            if accts & GENERIC:
                flags.append("GUEST/GENERIC")
            out(f"  {win} {who[:50]:50} reads={r['n']:<4} MB={r['mb']:<6.1f} tables={len(r['tables']):<3} {' '.join(flags)}")

    api_requests(logs, since, is_new, seen_before)

    rotated = sorted(n for n in logs if n.startswith("nginx-access.log-"))
    ng = [p for p in (l.split("\t") for l in lines(logs, *rotated, "nginx-access.log")) if len(p) >= 7]
    if not ng:
        out("\n## Web server (nginx-access.log): not supplied. This check reads nginx only:\n"
              "   read an IIS or Apache log by hand for /fmi/ paths and any .php page that answered")
        return
    out(f"\n## Web server (nginx-access.log): {len(ng)} requests, {ng[0][2][:16]} .. {ng[-1][2][:16]}")
    out("  status:", collections.Counter(p[4] for p in ng).most_common())
    fm = collections.Counter(
        (p[0], p[3].split(" ")[0].strip('"'), re.sub(r"\?.*", "", p[3].split(" ")[1]) if " " in p[3] else p[3], p[4])
        for p in ng if re.search(r"/(fmi|otto|admin-console|fmws)", p[3]) and "wpe/info" not in p[3])
    out("  FileMaker web paths (excluding uptime checks):")
    for k, n in fm.most_common(25):
        out(f"    {n:4} {k}")
    out("  busiest addresses:", collections.Counter(p[0] for p in ng).most_common(10))

    # PHP and XML. Scanners ask for .php pages on every server, so 404s are noise; a page that answered is not.
    phpxml = [p for p in ng if re.search(r"\.php\b|/fmi/xml|/fmi/php|/fmi-test|fmresultset|FMPXMLRESULT", p[3], re.I)]
    out(f"  PHP and XML requests: {len(phpxml)}, by status {collections.Counter(p[4] for p in phpxml).most_common()}")
    answered = collections.Counter((p[0], re.sub(r"\?.*", "", p[3].split(" ")[1]) if " " in p[3] else p[3], p[4])
                                   for p in phpxml if p[4].startswith("2"))
    for (ip, path, status), n in answered.most_common(15):
        out(f"    ANSWERED {n:4} {ip:40} {path} {status}")

    # Data API, OData and XML record reads, per address per 10 minutes (the Claris pattern:
    # many 200-record pages pulled from many layouts in a short time)
    # Only answered calls (2xx) returned records; refused ones (401, 403...) are counted apart.
    api = collections.defaultdict(lambda: dict(n=0, layouts=set()))
    refused = collections.Counter()
    for p in ng:
        m = re.search(r"/fmi/(?:data/[^/]+/databases/([^/]+)/layouts/([^/?]+)/(?:records|_find)|odata/v\d+/([^/?]+)/([^/?(]+)|xml/\w+\.xml\?(?=.*-db=([^&\s]+))(?=.*-lay=([^&\s]+)))", p[3])
        if not m:
            continue
        if not p[4].startswith("2"):
            refused[(p[0], p[4])] += 1
            continue
        r = api[(p[0], p[2][:15] + "0")]
        r["n"] += 1
        r["layouts"].add("/".join(x for x in m.groups() if x))
    out(f"  Data API, OData and XML record calls answered: {sum(r['n'] for r in api.values())}")
    if refused:
        out("  Refused record calls (no records returned): "
              + ", ".join(f"{ip} {status} x{n}" for (ip, status), n in refused.most_common(10)))
    for (ip, win), r in sorted(api.items(), key=lambda x: -x[1]["n"])[:10]:
        flag = "  BURST" if r["n"] >= API_CALLS or len(r["layouts"]) >= 5 else ""
        out(f"    {win} {ip:40} calls={r['n']:<5} layouts={len(r['layouts'])}{flag}")


if __name__ == "__main__":
    main()
