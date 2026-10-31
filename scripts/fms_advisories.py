#!/usr/bin/env python3
"""FMS advisories: published FileMaker security issues, and which affect a given version.

Fetches FileMaker CVEs live from NVD (one request), merges them with the skill's bundled list
(references/advisories.json: NVD CVEs tagged by product, plus FileMaker Server security fixes
Claris lists only in its release notes), and, given a version, lists every published issue that
version is still exposed to. Without network access it uses the bundled list and says how old
it is.

Products: FileMaker Server (default), FileMaker Pro clients (--pro). FileMaker Cloud issues are
listed but never matched: Claris patches its own hosting.

Usage:
    python3 fms_advisories.py                  # latest releases and all known issues
    python3 fms_advisories.py 22.0.3.1         # issues affecting this FileMaker Server
    python3 fms_advisories.py 25.0.1 --pro     # issues affecting this FileMaker Pro client
    python3 fms_advisories.py 22.0.3 --offline

Confirmed means published by NVD or Claris. Claims seen only on third-party sites are not
included. Uses only the Python standard library.
"""
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED = os.path.join(HERE, "..", "references", "advisories.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=FileMaker&resultsPerPage=200"
TIMEOUT = 20      # seconds; NVD can be slow, and one request is all this needs
SINCE = "2021"    # older CVEs affect only versions long out of support
PRODUCT = {"filemaker_server": "server", "filemaker_pro": "pro", "filemaker_pro_advanced": "pro",
           "claris_pro": "pro", "filemaker_cloud": "cloud"}
NAMES = {"server": "FileMaker Server", "pro": "FileMaker Pro", "cloud": "FileMaker Cloud"}


def vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def load_bundled():
    try:
        with open(BUNDLED, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"Can't read the bundled list at {BUNDLED}: {e}")


def fetch_nvd():
    """Return CVE entries from NVD in the bundled format, or None if NVD can't be reached."""
    req = urllib.request.Request(NVD, headers={"User-Agent": "cadenceux-fms-security"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.load(r)
    except (OSError, ValueError) as e:
        print(f"  (NVD not reachable: {e}; using the bundled list)")
        return None
    out = []
    for v in data.get("vulnerabilities", []):
        c = v["cve"]
        if c.get("published", "") < SINCE:
            continue
        ranges = []
        for conf in c.get("configurations", []):
            for n in conf.get("nodes", []):
                for m in n.get("cpeMatch", []):
                    parts = m.get("criteria", "").split(":")
                    prod = PRODUCT.get(parts[4]) if len(parts) > 4 else None
                    if prod and m.get("vulnerable") and m.get("versionEndExcluding"):
                        ranges.append({"product": prod, "from": m.get("versionStartIncluding"),
                                       "before": m["versionEndExcluding"]})
        if not ranges:
            continue          # not yet analysed by NVD, or not a FileMaker product
        metrics = c.get("metrics", {})
        score = next((metrics[k][0]["cvssData"]["baseScore"] for k in
                      ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30") if metrics.get(k)), None)
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        kb = next((r["url"] for r in c.get("references", []) if "claris.com" in r["url"]), "")
        entry = {"id": c["id"], "published": c["published"][:10], "cvss": score, "affected": ranges,
                 "source": kb or f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                 "summary": desc.split(". ")[0][:200]}
        platform = re.search(r"\b(Windows|macOS|Linux)\b", desc)
        if platform:
            entry["platform"] = platform.group(1)
        out.append(entry)
    return out


def affects(entry, version, product="server"):
    """Return the fixed version if entry affects this product version, else None."""
    v = vt(version)
    for r in entry["affected"]:
        if r.get("product", "server") != product:
            continue
        if (r["from"] is None or v >= vt(r["from"])) and v < vt(r["before"]):
            return r["before"]
    return None


def merged(data, live):
    cves = {c["id"]: c for c in data["cves"]}
    new = []
    for c in live or []:
        if c["id"] not in cves:
            new.append(c["id"])
        old = cves.get(c["id"], {})
        if "platform" in old and "platform" not in c:
            c["platform"] = old["platform"]
        cves[c["id"]] = c
    return list(cves.values()) + data["release_note_fixes"], new


def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        sys.exit(__doc__)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    product = "pro" if "--pro" in sys.argv else "server"
    data = load_bundled()
    live = None if "--offline" in sys.argv else fetch_nvd()
    entries, new = merged(data, live)
    if live is not None:
        print(f"##### Source: NVD live, plus Claris release-note fixes checked {data['checked']}")
    else:
        print(f"##### Source: bundled list, checked {data['checked']}. Anything published since is missing")
    if new:
        print(f"  New since the bundled list: {', '.join(new)}. Check each against its Claris source")
    latest = data["latest"]
    print(f"  Latest FileMaker Server releases at {data['checked']}: "
          + ", ".join(latest[k] for k in sorted(latest, key=int, reverse=True))
          + f". Newer may exist: {data['sources']['release_notes']}")
    server_fixes = [r["before"] for e in entries for r in e["affected"] if r.get("product", "server") == "server"]
    newest_fix = max(server_fixes, key=vt)
    for line, ver in latest.items():
        if vt(newest_fix)[0] == int(line) and vt(newest_fix) > vt(ver):
            print(f"  NVD lists a fix in {newest_fix}, newer than the bundled latest {ver}: check the release notes")

    if not args:
        for prod in ("server", "pro", "cloud"):
            rows = [e for e in entries if any(r.get("product", "server") == prod for r in e["affected"])]
            print(f"\n## {NAMES[prod]}: {len(rows)} known issue(s)"
                  + (" (Claris patches its own hosting; listed for reference)" if prod == "cloud" else ""))
            for e in sorted(rows, key=lambda x: x["published"], reverse=True):
                fixed = ", ".join(r["before"] for r in e["affected"] if r.get("product", "server") == prod)
                plat = f" [{e['platform']} only]" if e.get("platform") else ""
                print(f"  {e['id']:28} {str(e['cvss'] or '-'):4} fixed in {fixed}{plat}: {e['summary'][:80]}")
        return

    version = args[0]
    if not vt(version):
        sys.exit(f"Not a version number: {version}")
    hits = [(e, affects(e, version, product)) for e in entries]
    hits = sorted([(e, f) for e, f in hits if f], key=lambda x: -(x[0]["cvss"] or 0))
    line = vt(version)[0]
    print(f"\n## {NAMES[product]} {version}")
    if product == "server":
        if line < data["oldest_supported_line"]:
            print(f"  UNSUPPORTED: line {line} is older than {data['oldest_supported_line']}; it gets no security fixes")
        elif str(line) in latest and vt(version) < vt(latest[str(line)]):
            print(f"  Behind the latest {line}.x release ({latest[str(line)]})")
    print(f"  {len(hits)} published issue(s) affect this version" + (":" if hits else ""))
    for e, fixed in hits:
        same_line = vt(fixed)[0] == line
        fix = f"fixed in {fixed}" if same_line else \
            f"fixed in {fixed}; no {line}.x fix listed, so upgrade, or confirm in the source that {line}.x is affected"
        plat = f" ({e['platform']} only)" if e.get("platform") else ""
        print(f"  {str(e['cvss'] or '-'):4} {e['id']:28} {fix}{plat}\n       {e['summary'][:150]}\n       {e['source']}")


if __name__ == "__main__":
    main()
