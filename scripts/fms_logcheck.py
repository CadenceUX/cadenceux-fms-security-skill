#!/usr/bin/env python3
"""FMS log check: what happened on a FileMaker Server since a given time.

Reads a folder of FileMaker Server logs (or the .zip they came in) and reports:
new addresses, failed sign-ins with warning flags, Admin Console sign-ins,
security and file events, Admin API errors, bursts of record downloads,
and outside requests to FileMaker web paths. Uses only the Python
standard library.

Usage:
    python3 fms_logcheck.py <log folder or .zip> [since]

    since   "YYYY-MM-DD HH:MM" in the server's local time. If left out, the
            check covers the 24 hours before the newest Access.log entry.

Examples:
    python3 fms_logcheck.py ~/Downloads/server-logs.zip
    python3 fms_logcheck.py ./Logs "2026-10-28 01:00"

Read-only: it never changes the logs. A .zip is extracted to a temporary folder.
See references/log-review.md in the cadenceux-fms-security skill for what each
flag means and when to escalate.
"""
import collections
import datetime
import ipaddress
import os
import re
import sys
import tempfile
import zipfile

GENERIC = {"", "admin", "administrator", "web", "webuser", "user", "api", "apiuser",
           "test", "guest", "[guest]", "filemaker"}
IP = r"(\d+\.\d+\.\d+\.\d+|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})"
LOCAL = {"127.0.0.1", "::1"}
DOWNLOAD_MB = 20      # per client per 10 minutes; busy production servers peaked near 6 MB
WIDE_TABLES = 40      # developers reach 60+ tables, so WIDE needs a NEW or GUEST/GENERIC client too
API_CALLS = 100       # Data API / OData record calls per address per 10 minutes (attackers page 200 at a time)


def open_logs(path):
    """Return a dict of log file name -> full path, extracting a .zip first."""
    path = os.path.expanduser(path)
    if path.lower().endswith(".zip"):
        out = tempfile.mkdtemp(prefix="fms_logcheck_")
        with zipfile.ZipFile(path) as z:
            for m in z.infolist():
                name = os.path.basename(m.filename)
                if name.endswith(".log") and not m.is_dir():
                    with z.open(m) as src, open(os.path.join(out, name), "wb") as dst:
                        dst.write(src.read())
        path = out
    found = {}
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".log"):
                found.setdefault(f, os.path.join(root, f))
    return found


def lines(logs, *names):
    for n in names:
        if n in logs:
            with open(logs[n], encoding="utf-8-sig", errors="replace") as f:
                for l in f:
                    yield l.rstrip("\n")


def fms_advisories_vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def ip_of(text):
    m = re.search(r"[\[(]" + IP + r"[\])]", text)
    return m.group(1) if m else None


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    logs = open_logs(sys.argv[1])
    if "Access.log" not in logs or "Event.log" not in logs:
        sys.exit("Access.log and Event.log are needed; found: " + ", ".join(sorted(logs)))
    if len(sys.argv) > 2:
        since = sys.argv[2]
    else:
        last = max(l[:16] for l in lines(logs, "Access.log") if l[:4].isdigit())
        since = (datetime.datetime.strptime(last, "%Y-%m-%d %H:%M") - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")

    # Access log: who connected, and which addresses are new
    seen_before = set()
    after = collections.defaultdict(lambda: dict(n=0, pc=set(), app=set(), acct=set(), first=None, last=None))
    succeeded = set()
    for l in lines(logs, "Access-old.log", "Access.log"):
        ts, ip = l[:16], ip_of(l)
        if not ip or not ts[:4].isdigit():
            continue
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
        if "opening database" in l:
            succeeded.add(ip)

    # Event log: addresses seen before the window also count as known
    for l in lines(logs, "Event.log"):
        if l[:16] < since and l[:4].isdigit():
            ip = ip_of(l)
            if ip and ("connected" in l or "opening" in l):
                seen_before.add(ip)

    # A window that starts at or before the first log entry has nothing to compare with
    first_review = not seen_before

    def is_new(ip):
        return not first_review and ip not in seen_before and ip not in LOCAL

    print(f"##### FMS log check: {since} onward")
    print(f"Files: {', '.join(sorted(logs))}")
    print(f"\n## Connections (Access.log): {len(after)} addresses, {sum(r['n'] for r in after.values())} lines")
    if first_review:
        print("   First review: the window starts at the first log entry, so no address can be marked NEW")
    else:
        print("   NEW = address not seen before the window")
    private = [ip for ip in after if ipaddress.ip_address(ip).is_private]
    if after and len(private) == len(after):
        print("   All addresses are private: the server is behind NAT, a proxy, a load balancer or a container\n"
              "   gateway, so these logs don't show real client addresses. Check the edge firewall or proxy logs")
    for ip, r in sorted(after.items(), key=lambda x: -x[1]["n"]):
        flag = "NEW " if is_new(ip) else "    "
        print(f"{flag}{ip:40} n={r['n']:<6} {r['first']}..{r['last'][5:]} pc={sorted(r['pc'])[:3]} "
              f"app={sorted(r['app'])[:2]} acct={sorted(r['acct'])[:5]}")

    fails = collections.defaultdict(lambda: dict(n=0, acct=set(), files=set(), chan=set()))
    admin, admin_fail, other = collections.Counter(), collections.Counter(), collections.Counter()
    for l in lines(logs, "Event.log"):
        if l[:16] < since or not l[:4].isdigit():
            continue
        msg = l.split("\t", 4)[-1]
        if "authentication failed on database" in msg:
            r = fails[ip_of(msg) or "?"]
            r["n"] += 1
            m = re.search(r'on database "([^"]+)" using "(?:([^"]*?) )?\[(\w+)\]"', msg)
            if m:
                r["files"].add(m.group(1))
                r["acct"].add(m.group(2) or "")
                r["chan"].add(m.group(3))
        elif "Administrator authentication failed" in msg:
            admin_fail[ip_of(msg)] += 1
        elif "Administrator connected" in msg:
            m = re.search(r'"(\S+) \[([^\]]+)\]" \(([^)]+)\)', msg)
            if m:
                admin[(m.group(2), m.group(1), m.group(3))] += 1
        elif re.search(r"SECURITY|upload|removed|Guest|Schedule .* (created|modified|deleted)|setting|changed", msg, re.I) \
                and "Secure (SSL)" not in msg:
            other[re.sub(r"\d", "#", msg)[:150]] += 1

    print(f"\n## Failed FileMaker sign-ins: {sum(r['n'] for r in fails.values())} from {len(fails)} addresses")
    print("   Flags: NEVER-SUCCEEDED, MANY-ACCOUNTS (3+), MANY-FILES (3+), GENERIC/DEFAULT account")
    for ip, r in sorted(fails.items(), key=lambda x: -x[1]["n"]):
        flags = []
        if ip not in seen_before and ip not in succeeded and ip not in LOCAL:
            flags.append("NEVER-SUCCEEDED")
        if len(r["acct"]) >= 3:
            flags.append("MANY-ACCOUNTS")
        if len(r["files"]) >= 3:
            flags.append("MANY-FILES")
        if {a.lower() for a in r["acct"]} & GENERIC:
            flags.append("GENERIC/DEFAULT")
        print(f"  {ip:40} n={r['n']:<4} accts={sorted(r['acct'])[:5]} files={len(r['files'])} "
              f"via={sorted(r['chan'])} {' '.join(flags)}")

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
        print(f"\n## Client versions (Access.log): {len(clients)} FileMaker Pro/Go build(s)")
        for (kind, ver), c in sorted(clients.items(), key=lambda x: fms_advisories_vt(x[0][1])):
            note = ""
            if adv and kind.startswith("Pro"):
                hits = [(e, fms_advisories.affects(e, ver, "pro")) for e in adv["cves"]]
                hits = [f"{e['id']} (fixed {f}{', ' + e['platform'] + ' only' if e.get('platform') else ''})"
                        for e, f in hits if f]
                if hits:
                    note = "  UPDATE: " + "; ".join(hits)
            print(f"  {kind + ' ' + ver:24} {c['n']:3} address(es), e.g. {', '.join(sorted(c['where'])[:3])}{note}")

    print("\n## Admin Console / fmsadmin sign-ins")
    for (ip, acct, how), n in admin.most_common():
        flags = ("  NEW" if is_new(ip) else "") + ("  GENERIC" if acct.lower() in GENERIC else "")
        print(f"  {n:4} {ip:40} {acct} ({how}){flags}")
    print(f"## Admin sign-in failures: {dict(admin_fail) or 'none'}")

    print("\n## Security, settings and file events")
    for k, n in other.most_common(30):
        print(f"  {n:4} {k}")

    fac = [l for l in lines(logs, "fac.log") if l[:16] >= since and re.search(r"error", l, re.I) and "Data Storage" not in l]
    print(f"\n## Admin API errors (fac.log): {len(fac)}")
    for k, n in collections.Counter(re.sub(r"^\S+ \S+ \S+", "", re.sub(r"\d", "#", l))[:140] for l in fac).most_common(10):
        print(f"  {n:4} {k}")

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
        print("\n## Record downloads (TopCallStats.log): not supplied")
    else:
        print(f"\n## Record downloads (TopCallStats.log): {len(reads)} client 10-minute windows")
        print(f"   Flags: HIGH-VOLUME ({DOWNLOAD_MB}+ MB), WIDE ({WIDE_TABLES}+ tables) on a NEW address "
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
            print(f"  {win} {who[:50]:50} reads={r['n']:<4} MB={r['mb']:<6.1f} tables={len(r['tables']):<3} {' '.join(flags)}")

    ng = [p for p in (l.split("\t") for l in lines(logs, "nginx-access.log")) if len(p) >= 7]
    if not ng:
        print("\n## Web server (nginx-access.log): not supplied")
        return
    print(f"\n## Web server (nginx-access.log): {len(ng)} requests, {ng[0][2][:16]} .. {ng[-1][2][:16]}")
    print("  status:", collections.Counter(p[4] for p in ng).most_common())
    fm = collections.Counter(
        (p[0], p[3].split(" ")[0].strip('"'), re.sub(r"\?.*", "", p[3].split(" ")[1]) if " " in p[3] else p[3], p[4])
        for p in ng if re.search(r"/(fmi|otto|admin-console|fmws)", p[3]) and "wpe/info" not in p[3])
    print("  FileMaker web paths (excluding uptime checks):")
    for k, n in fm.most_common(25):
        print(f"    {n:4} {k}")
    print("  busiest addresses:", collections.Counter(p[0] for p in ng).most_common(10))

    # Data API and OData record reads, per address per 10 minutes (the Claris pattern:
    # many 200-record pages pulled from many layouts in a short time)
    # Only answered calls (2xx) returned records; refused ones (401, 403...) are counted apart.
    api = collections.defaultdict(lambda: dict(n=0, layouts=set()))
    refused = collections.Counter()
    for p in ng:
        m = re.search(r"/fmi/(?:data/[^/]+/databases/([^/]+)/layouts/([^/?]+)/(?:records|_find)|odata/v\d+/([^/?]+)/([^/?(]+))", p[3])
        if not m:
            continue
        if not p[4].startswith("2"):
            refused[(p[0], p[4])] += 1
            continue
        r = api[(p[0], p[2][:15] + "0")]
        r["n"] += 1
        r["layouts"].add("/".join(x for x in m.groups() if x))
    print(f"  Data API / OData record calls answered: {sum(r['n'] for r in api.values())}")
    if refused:
        print("  Refused record calls (no records returned): "
              + ", ".join(f"{ip} {status} x{n}" for (ip, status), n in refused.most_common(10)))
    for (ip, win), r in sorted(api.items(), key=lambda x: -x[1]["n"])[:10]:
        flag = "  BURST" if r["n"] >= API_CALLS or len(r["layouts"]) >= 5 else ""
        print(f"    {win} {ip:40} calls={r['n']:<5} layouts={len(r['layouts'])}{flag}")


if __name__ == "__main__":
    main()
