#!/usr/bin/env python3
"""FMS service advisories: published issues for the services a server shows to the internet.

Reads the JSON fms_exposure_check.py writes with --services-json, and for each service that gave away a version:

  * an Ubuntu package (an SSH greeting such as OpenSSH_8.9p1 Ubuntu-3ubuntu0.10) is checked against Ubuntu's own
    security data for that release, which says exactly which package version fixed each CVE. Ubuntu fixes
    without changing the upstream version, so NVD's version ranges would flag fixed packages. The data comes
    from OSV.dev, which carries Ubuntu's records and compares package versions itself, in one request; Ubuntu's
    own API (20 CVEs a request, and on 12 November 2026 up to 50 seconds each) is the fallback.
  * anything else with a version is looked up on NVD by its CPE (product and version), and each CVE is kept only
    when NVD lists that version as vulnerable.

It also reports whether the operating system the services name is still supported, from
references/os-lifecycle.json.

Only product names, versions and package names leave this Mac, never a hostname or an address. Without network
access, or with --offline or FMS_SCANNER_OFFLINE set, nothing is looked up and the report says so.

Usage:
    python3 fms_service_advisories.py <services.json> [--offline] [--json <path>]

Uses only the Python standard library.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LIFECYCLE = os.path.join(HERE, "..", "references", "os-lifecycle.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UBUNTU = "https://ubuntu.com/security/cves.json"
OSV = "https://api.osv.dev/v1/query"
# OSV's name for each Ubuntu LTS release the SSH greeting can name
UBUNTU_RELEASES = {"bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04"}
TIMEOUT = 30
NVD_GAP = 6.5      # seconds between NVD requests: without an API key NVD allows 5 in 30 seconds
UBUNTU_PAGE = 20   # the most Ubuntu's API returns per request
OPEN_STATUSES = {"needed": "no Ubuntu fix yet", "pending": "Ubuntu fix pending", "deferred": "Ubuntu deferred the fix"}
SKIP_STATUSES = {"not-affected", "ignored", "DNE"}


# ---- Version comparison ----

def upstream_key(v):
    """8.9p1 -> (8, 9, 'p', 1), so 8.9 < 8.9p1 < 9.0 and 2.4.6 < 2.4.58."""
    return tuple((0, int(t)) if t.isdigit() else (-1, t) for t in re.findall(r"\d+|[a-z]+", (v or "").lower()))


def _order(c):
    """dpkg's character order: digits 0, letters by code, ~ before everything (even the end), other symbols after."""
    return 0 if c.isdigit() else ord(c) if c.isalpha() else -1 if c == "~" else ord(c) + 256


def _verrevcmp(a, b):
    """dpkg's verrevcmp(), translated line for line: compare text runs by _order, then digit runs as numbers."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def dpkg_compare(a, b):
    """Negative, 0 or positive, as `dpkg --compare-versions` decides for [epoch:]upstream[-revision]."""
    def split(v):
        epoch, rest = v.split(":", 1) if ":" in v else ("0", v)
        upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), upstream, revision
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def severity(score, priority=""):
    if score is not None:
        return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else ""
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "negligible": "Low"}.get(priority, "")


# ---- Lookups. get(url) returns parsed JSON; tests pass their own ----

def http_get(url, body=None):
    """One GET, or a POST of body as JSON, tried again once after a timeout or a server error: Ubuntu's API
    sometimes takes 50 seconds and gives a 504."""
    headers = {"User-Agent": "cadenceux-fms-security"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, headers=headers, data=json.dumps(body).encode() if body is not None else None)
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if attempt == 2 or e.code < 500:
                raise
        except OSError as e:   # socket.timeout on Python 3.9, macOS's own; URLError wraps it when connecting
            if attempt == 2 or "timed out" not in str(e):
                raise
        time.sleep(3)


def in_range(match, version):
    """Whether one NVD cpeMatch entry covers this upstream version."""
    parts = match.get("criteria", "").split(":")
    exact, update = (parts[5] if len(parts) > 5 else "*"), (parts[6] if len(parts) > 6 else "*")
    k = upstream_key(version)
    if exact not in ("*", "-"):
        base = re.match(r"\d+(?:\.\d+)*", version).group(0)
        tail = version[len(base):]
        return exact == base and (update in ("*", "-") and not tail or update == tail or update == "*")
    lo_inc, lo_exc = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    hi_inc, hi_exc = match.get("versionEndIncluding"), match.get("versionEndExcluding")
    if not any((lo_inc, lo_exc, hi_inc, hi_exc)):
        return False   # every version: too broad to say anything about this one
    return ((not lo_inc or k >= upstream_key(lo_inc)) and (not lo_exc or k > upstream_key(lo_exc)) and
            (not hi_inc or k <= upstream_key(hi_inc)) and (not hi_exc or k < upstream_key(hi_exc)))


def nvd_issues(cpe, version, get=http_get):
    """CVEs NVD lists this product version as vulnerable to. Pages through NVD's results."""
    vendor_product = ":".join(cpe.split(":")[3:5])
    issues, start = [], 0
    while True:
        q = urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": 200, "startIndex": start})
        data = get(f"{NVD}?{q}")
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            hit = any(m.get("vulnerable") and ":".join(m.get("criteria", "").split(":")[3:5]) == vendor_product
                      and in_range(m, version)
                      for conf in c.get("configurations", []) for n in conf.get("nodes", []) for m in n.get("cpeMatch", []))
            if not hit:
                continue
            metrics = c.get("metrics", {})
            score = next((metrics[k][0]["cvssData"]["baseScore"] for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30")
                          if metrics.get(k)), None)
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            issues.append({"id": c["id"], "published": c.get("published", "")[:10], "cvss": score,
                           "severity": severity(score), "status": "affects this version", "fixed": "",
                           "summary": " ".join(desc.split()).split(". ")[0][:200]})
        start += data.get("resultsPerPage", 0) or 200
        if start >= data.get("totalResults", 0):
            break
        time.sleep(NVD_GAP)
    return sorted(issues, key=lambda i: (-(i["cvss"] or 0), i["id"]))


def ubuntu_issues(package, codename, installed, get=http_get):
    """CVEs Ubuntu's data says this installed package version is still exposed to, and how many it has fixed."""
    issues, fixed, untriaged, offset = [], 0, 0, 0
    while True:
        q = urllib.parse.urlencode({"package": package, "version": codename, "limit": UBUNTU_PAGE, "offset": offset})
        data = get(f"{UBUNTU}?{q}")
        for c in data.get("cves", []):
            st = next((s for p in c.get("packages", []) if p.get("name") == package for s in p.get("statuses", [])
                       if s.get("release_codename") == codename), None)
            if not st or st["status"] in SKIP_STATUSES:
                continue
            score = c.get("cvss3")
            score = score if isinstance(score, (int, float)) else None
            entry = {"id": c["id"], "published": str(c.get("published", ""))[:10], "cvss": score,
                     "severity": severity(score, c.get("priority", "")), "fixed": "",
                     "summary": " ".join((c.get("description") or "").split()).split(". ")[0][:200]}
            if st["status"] == "released":
                if dpkg_compare(installed, st.get("description", "")) >= 0:
                    fixed += 1
                    continue
                entry.update(status="fixed in a newer package", fixed=st.get("description", ""))
            elif st["status"] in OPEN_STATUSES:
                entry["status"] = OPEN_STATUSES[st["status"]]
            else:
                untriaged += 1
                continue
            issues.append(entry)
        offset += UBUNTU_PAGE
        if offset >= data.get("total_results", 0) or not data.get("cves"):
            break
        time.sleep(0.5)
    return sorted(issues, key=lambda i: (-(i["cvss"] or 0), i["id"])), fixed, untriaged


# CVSS 3.x base score from its vector, by the specification's formula (FIRST, CVSS v3.1 section 7)
CVSS_WEIGHTS = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
                "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x):
    n = round(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (n // 10000 + 1) / 10.0


def cvss3_score(vector):
    """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8. None when the vector can't be read."""
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        w = CVSS_WEIGHTS
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - w["CIA"][m["C"]]) * (1 - w["CIA"][m["I"]]) * (1 - w["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * w["AV"][m["AV"]] * w["AC"][m["AC"]] * pr * w["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + exploit), 10))


def osv_ubuntu_issues(package, codename, installed, get=http_get):
    """The same answer as ubuntu_issues, from OSV.dev's copy of Ubuntu's data: one request, versions compared by OSV.

    OSV returns each CVE as a UBUNTU-CVE record, and each Ubuntu security notice again as a USN record; only the
    CVE records are kept. A fix released only through Ubuntu Pro (ESM) is named as that. Checked against Ubuntu's
    API for openssh 1:8.9p1-3ubuntu0.10 on jammy (13 November 2026): the same 31 CVEs, fixes and scores."""
    release = UBUNTU_RELEASES[codename]
    eco, pro = f"Ubuntu:{release}:LTS", f"Ubuntu:Pro:{release}:LTS"
    # An installed package from Ubuntu Pro has +esm in its version, and its fixes are in the Pro records
    mine = pro if "esm" in installed else eco
    issues, token = [], None
    while True:
        query = {"package": {"name": package, "ecosystem": mine}, "version": installed}
        if token:
            query["page_token"] = token
        data = get(OSV, query)
        for v in data.get("vulns", []):
            if not v["id"].startswith("UBUNTU-CVE-"):
                continue
            def fix_in(ecosystem):
                return next((e["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("ecosystem") == ecosystem
                             and a["package"].get("name") == package for r in a.get("ranges", [])
                             for e in r.get("events", []) if "fixed" in e), "")
            fixed, pro_fix = fix_in(mine), "" if mine == pro else fix_in(pro)
            if fixed and dpkg_compare(installed, fixed) >= 0:
                continue   # OSV said affected, but this version already has the fix: trust the comparison
            # The first CVSS vector is Ubuntu's own; a second is usually the reporter's, and often far higher.
            # Ubuntu's API gives the first one's score (checked on 31 CVEs, 13 November 2026), so this does too.
            score = next((cvss3_score(x["score"]) for x in v.get("severity", []) if x.get("type") == "CVSS_V3"), None)
            priority = next((x["score"] for x in v.get("severity", []) if x.get("type") == "Ubuntu"), "")
            if not fixed and priority == "negligible":
                continue   # Ubuntu doesn't fix these, and its own API leaves them out; OSV's record has no status to say so
            cve = (v.get("upstream") or [v["id"][len("UBUNTU-"):]])[0]
            entry = {"id": cve, "published": str(v.get("published", ""))[:10], "cvss": score,
                     "severity": severity(score, priority), "fixed": fixed,
                     "summary": " ".join((v.get("details") or "").split()).split(". ")[0][:200]}
            if fixed:
                entry["status"] = "fixed in a newer package"
            elif pro_fix and dpkg_compare(installed, pro_fix) < 0:
                entry.update(status="fixed only in Ubuntu Pro", fixed=pro_fix)
            else:
                entry["status"] = "no Ubuntu fix yet"
            issues.append(entry)
        token = data.get("next_page_token")
        if not token:
            break
    return sorted(issues, key=lambda i: (-(i["cvss"] or 0), i["id"])), 0, 0


def os_support(system, lifecycle, today=None):
    """Whether the named operating system release still gets security fixes."""
    today = today or time.strftime("%Y-%m-%d")
    name, release = system.get("name", ""), system.get("release", "")
    out = {"name": name, "release": release, "state": "unknown", "text": ""}
    if not name:
        out["text"] = "no open service names the operating system"
        return out
    if name == "Windows":
        entry = next((w for w in lifecycle.get("windows", []) if w["name"] == release), None)
        if entry and entry.get("ends"):
            out.update(state="unsupported" if entry["ends"] < today else "supported", ends=entry["ends"])
            out["text"] = (f"{release}: OUT OF SUPPORT since {entry['ends']}, so it gets no security fixes"
                           if entry["ends"] < today else f"{release}: supported until {entry['ends']}")
        else:
            out["text"] = f"{release or 'Windows'}: release or support date not known to this scan"
        return out
    if name == "Ubuntu":
        entry = next((u for u in lifecycle.get("ubuntu", []) if u["release"] == release), None)
        if entry:
            std, esm = entry["standard_ends"], entry["esm_ends"]
            if esm < today[:7]:
                out.update(state="unsupported", text=f"Ubuntu {release}: OUT OF SUPPORT since {esm}, even with Ubuntu Pro")
            elif std < today[:7]:
                out.update(state="esm", text=f"Ubuntu {release}: standard support ended {std}; security fixes only "
                                             f"with Ubuntu Pro (ESM) until {esm}. Check that Ubuntu Pro is attached")
            else:
                out.update(state="supported", text=f"Ubuntu {release}: supported until {std} (with Ubuntu Pro until {esm})")
        else:
            out["text"] = f"Ubuntu {release or ''}: release not identified, so its support can't be checked".replace("  ", " ")
        return out
    if name == "Debian":
        entry = next((d for d in lifecycle.get("debian", []) if d["release"] == release), None)
        if entry and entry.get("lts_ends"):
            sec, lts = entry["security_ends"], entry["lts_ends"]
            if lts < today:
                out.update(state="unsupported", text=f"Debian {release}: OUT OF SUPPORT since {lts}")
            elif sec and sec < today:
                out.update(state="esm", text=f"Debian {release}: regular security support ended {sec}; LTS until {lts}")
            else:
                out.update(state="supported", text=f"Debian {release}: supported" + (f" until {sec}" if sec else ""))
        else:
            out["text"] = f"Debian {release}: support dates not known to this scan".replace("  ", " ")
        return out
    out["text"] = f"{name}: its release isn't visible from outside, so its support can't be checked"
    return out


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        sys.exit(__doc__)
    offline = "--offline" in args or bool(os.environ.get("FMS_SCANNER_OFFLINE"))
    json_out = args[args.index("--json") + 1] if "--json" in args[:-1] else ""
    with open(args[0], encoding="utf-8") as f:
        scan = json.load(f)
    try:
        with open(LIFECYCLE, encoding="utf-8") as f:
            lifecycle = json.load(f)
    except (OSError, ValueError):
        lifecycle = {}
    services = scan.get("services", [])
    support = os_support(scan.get("os") or {}, lifecycle)
    print(f"##### FMS service advisories: {len(services)} services"
          + (" (offline: nothing looked up)" if offline else f", looked up {time.strftime('%Y-%m-%d %H:%M')}"))
    print(f"## OS support: {support['text']}" + (f" (dates checked {lifecycle['checked']})" if lifecycle.get("checked") else ""))
    out, skipped, cache, last_nvd = [], [], {}, 0.0
    for s in services:
        label = " ".join(x for x in (s.get("product"), s.get("version")) if x)
        ubuntu = s.get("package") and s.get("codename") and s.get("package_version")
        if not ubuntu and not (s.get("matchable") and s.get("cpe")):
            why = s.get("note") or ("no version shown" if not s.get("version") else "not matched by version")
            skipped.append({"port": s["port"], "product": label, "why": why})
            continue
        entry = {"port": s["port"], "product": label, "issues": [], "fixed": 0, "untriaged": 0}
        if offline:
            entry.update(source="not looked up (offline)")
            out.append(entry)
            continue
        key = ("ubuntu", s["package"], s["codename"], s["package_version"]) if ubuntu else ("nvd", s["cpe"], s["version"])
        try:
            if key not in cache:
                if ubuntu:
                    try:
                        cache[key] = osv_ubuntu_issues(s["package"], s["codename"], s["package_version"]) + ("OSV.dev",)
                    except (OSError, ValueError, KeyError):
                        cache[key] = ubuntu_issues(s["package"], s["codename"], s["package_version"]) + ("Ubuntu",)
                else:
                    wait = NVD_GAP - (time.monotonic() - last_nvd)
                    if last_nvd and wait > 0:
                        time.sleep(wait)
                    cache[key] = (nvd_issues(s["cpe"], s["version"]), 0, 0, "NVD")
                    last_nvd = time.monotonic()
            entry["issues"], entry["fixed"], entry["untriaged"], via = cache[key]
            # The newest package version among the open issues' fixes: updating to it fixes every one that has a fix
            for fix in (i["fixed"] for i in entry["issues"] if i.get("fixed")):
                if not entry.get("update_to") or dpkg_compare(fix, entry["update_to"]) > 0:
                    entry["update_to"] = fix
            entry["source"] = (f"Ubuntu's security data for {s['codename']}, package {s['package_version']}"
                               + (", through OSV.dev" if via == "OSV.dev" else "") if ubuntu else "NVD, by version")
        except (OSError, ValueError, KeyError) as e:
            entry["source"] = f"couldn't be looked up ({e.__class__.__name__}: {str(e)[:80]})"
        if s.get("note") and not ubuntu:
            entry["note"] = s["note"]
        out.append(entry)
    for e in out:
        print(f"\n## {e['port']} {e['product']}: {e['source']}")
        if e.get("note"):
            print(f"  note: {e['note']}")
        for i in e["issues"]:
            fix = f"  {i['status']}" + (f" {i['fixed']}" if i["fixed"] else "")
            print(f"  {(str(i['cvss']) if i['cvss'] is not None else '-'):5} {i['severity'] or '-':9} {i['id']:18}{fix}  {i['summary']}")
        if not e["issues"] and not e["source"].startswith(("couldn't", "not looked")):
            print("  no published issues for this version")
        if e["fixed"] or e["untriaged"]:
            print(f"  ({e['fixed']} fixed in this package version" + (f", {e['untriaged']} not yet assessed by Ubuntu" if e["untriaged"] else "") + ")")
    if skipped:
        print("\n## Not looked up")
        for k in skipped:
            print(f"  {k['port']:<6} {k['product'] or 'not identified'}: {k['why']}")
    print("\n## Not visible from outside: the operating system's patch level and kernel, and anything behind a sign-in. "
          "Published issues for those need the server's own updates, not this scan.")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({"offline": offline, "os_support": support, "services": out, "not_looked_up": skipped,
                       "lifecycle_checked": lifecycle.get("checked", "")}, f, indent=1)


if __name__ == "__main__":
    main()
