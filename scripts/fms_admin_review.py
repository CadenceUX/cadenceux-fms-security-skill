#!/usr/bin/env python3
"""FMS admin review: read a FileMaker Server's security settings through the Admin API.

Run this YOURSELF, in your own terminal. It asks for an Admin Console account and
password, signs in to the Admin API, reads settings with GET requests only, signs out,
and prints PASS / REVIEW / FAIL lines. It never stores, prints or sends the password
anywhere except to your server, and changes nothing.

Usage:
    python3 fms_admin_review.py <hostname> [--insecure]

    --insecure  accept an untrusted certificate (the default Claris test certificate,
                or a self-signed one). The certificate is still reported as a finding.

Needs FileMaker Server 21 or later (some checks need 21.0.1+) and Python 3, standard
library only. Paste the output, not the password, back into the conversation.
"""
import base64
import getpass
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

TIMEOUT = 20      # seconds per request; Admin API calls on a busy server can take several seconds

# Latest patched release per supported line, from Claris's FileMaker Server release notes,
# checked 2026-10-31. Newer releases may exist: check
# https://help.claris.com/en/server-release-notes/content/ before relying on this.
LATEST = {26: (26, 0, 3), 22: (22, 0, 7), 21: (21, 1, 8)}
OLDEST_SUPPORTED = 21
RISKY_EXTPRIV = {"fmrest": "Data API", "fmodata": "OData", "fmxml": "XML", "fmxdbc": "ODBC/JDBC",
                 "fmphp": "PHP"}
GENERIC = {"[guest]", "guest", "admin", "administrator", "web", "user", "api", "test", ""}

results = []


def report(level, area, text):
    results.append((level, area, text))
    print(f"  {level:6} {area:14} {text}")


class Api:
    def __init__(self, host, insecure):
        self.base = f"https://{host}/fmi/admin/api/v2"
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE
        self.token = None

    def call(self, method, path, auth=None):
        req = urllib.request.Request(self.base + path, method=method, data=b"" if method == "POST" else None,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": auth or f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.ctx) as r:
                body = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read() or b"{}")
            except ValueError:
                body = {}
            msgs = body.get("messages") or body.get("message") or []
            text = msgs[0].get("text") if msgs and isinstance(msgs, list) else e.reason
            raise RuntimeError(f"HTTP {e.code}: {text}") from None
        return body.get("response", body)

    def get(self, path):
        try:
            return self.call("GET", path)
        except RuntimeError as e:
            hint = "; this check may need a newer version" if "HTTP 404" in str(e) else ""
            print(f"  -      {path:14} not read ({e}){hint}")
            return None


def find_key(obj, pattern):
    """Return the first string value whose key matches pattern, searching nested objects."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if re.search(pattern, k, re.I) and isinstance(v, str):
                return v
        for v in obj.values():
            found = find_key(v, pattern)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_key(v, pattern)
            if found:
                return found
    return ""


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    if not sys.stdin.isatty():
        sys.exit("Run this in your own terminal: it asks for the Admin Console password and must not "
                 "be given one by another program.")
    host = sys.argv[1].replace("https://", "").strip("/")
    api = Api(host, "--insecure" in sys.argv)
    user = input("Admin Console account: ")
    pw = getpass.getpass("Password (not shown): ")
    basic = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    del pw
    try:
        api.token = api.call("POST", "/user/auth", auth=basic)["token"]
    except ssl.SSLCertVerificationError:
        sys.exit("The certificate isn't trusted. That is itself a finding (see the certificate check); "
                 "re-run with --insecure to continue.")
    except (RuntimeError, OSError, KeyError) as e:
        sys.exit(f"Sign-in failed: {e}")

    try:
        print(f"##### FMS admin review: {host}\n")
        meta = api.get("/server/metadata") or {}
        v = meta.get("serverVersion") or find_key(meta, r"version")
        vt = version_tuple(v)
        if not vt:
            keys = sorted(meta) if isinstance(meta, dict) else type(meta).__name__
            report("REVIEW", "Version", f"version not found in /server/metadata (keys: {keys}); "
                   "read it from the Admin Console dashboard")
        elif vt[0] < OLDEST_SUPPORTED:
            report("FAIL", "Version", f"{v}: older than FileMaker Server 2024 (21); upgrade")
        elif vt[0] in LATEST and vt < LATEST[vt[0]]:
            report("FAIL", "Version", f"{v}: behind {'.'.join(map(str, LATEST[vt[0]]))}, which fixes "
                   "published security issues")
        else:
            report("PASS", "Version", f"{v} (re-check the release notes for anything newer)")
        if vt:
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                import fms_advisories
                adv = fms_advisories.load_bundled()
                hits = [e for e in adv["cves"] + adv["release_note_fixes"] if fms_advisories.affects(e, v)]
                if hits:
                    worst = max((e["cvss"] or 0) for e in hits)
                    report("FAIL" if worst >= 7 else "REVIEW", "Advisories",
                           f"{len(hits)} published issue(s) affect {v} (highest CVSS {worst or '-'}); details: "
                           f"python3 fms_advisories.py {v}")
            except (ImportError, SystemExit, OSError, KeyError):
                pass

        cert = (api.get("/server/certificate/info") or {}).get("certificate", {})
        if "Claris" in cert.get("issuerName", "") or "Not for Production" in cert.get("subjectName", ""):
            report("FAIL", "Certificate", "default Claris test certificate; install a trusted one")
        elif re.search(r"mkcert|development", cert.get("issuerName", ""), re.I):
            report("REVIEW", "Certificate", f"development CA ({cert.get('issuerName')}): trusted only on machines "
                   "that installed it; fine for a local test server, not for one others connect to")
        elif cert:
            report("PASS", "Certificate", f"issued by {cert.get('issuerName')}")

        sec = api.get("/server/config/security") or {}
        if "requireSecureDB" in sec:
            report("PASS" if sec["requireSecureDB"] else "FAIL", "Secure files",
                   "only password-protected files can be hosted" if sec["requireSecureDB"] else
                   "files with Guest [Full Access], blank or stored full-access passwords can be hosted")

        ra = api.get("/server/restrictaccess") or {}
        if "restrictIPEnabled" in ra:
            ips = [x for x in re.split(r"[,\s]+", ra.get("restrictIPList", "")) if x]
            report("PASS" if ra["restrictIPEnabled"] else "FAIL", "Admin access",
                   f"Admin Console restricted to {len(ips)} address(es)" if ra["restrictIPEnabled"] else
                   "Admin Console reachable from any address")

        vis = api.get("/fmclients/databasevisibility") or {}
        if "databaseVisibility" in vis:
            report("PASS" if vis["databaseVisibility"] else "FAIL", "Filter files",
                   "Filter databases in client applications is on" if vis["databaseVisibility"] else
                   "hosted file list shown to anyone who connects")

        bnu = api.get("/server/config/blocknewusers") or {}
        if bnu.get("blockNewUsers"):
            report("INFO", "Block users", "Block New Users is ON: new connections are refused")

        on = []
        for path, name in (("/fmdapi/config", "Data API"), ("/fmodata/config", "OData"),
                           ("/xdbc/config", "ODBC/JDBC"), ("/webdirect/config", "WebDirect"),
                           ("/xml/config", "XML"), ("/php/config", "PHP")):
            cfg = api.get(path) or {}
            if cfg.get("enabled"):
                on.append(name)
        report("REVIEW" if on else "PASS", "Services",
               f"enabled: {', '.join(on)}; turn off any not in use" if on else "no web or SQL services enabled")

        dbs = (api.get("/databases") or {}).get("databases", [])
        for d in dbs:
            name = d.get("filename", "?")
            risky = [RISKY_EXTPRIV[p] for p in d.get("enabledExtPrivileges", []) if p in RISKY_EXTPRIV]
            if risky:
                report("REVIEW", "File access", f"{name}: {', '.join(risky)} access enabled in at least one "
                       "privilege set; confirm each is needed")
            if d.get("isEncrypted") is False:
                report("REVIEW", "Encryption", f"{name}: not encrypted at rest")
        if not dbs:
            report("INFO", "Files", "no hosted files reported")

        for c in (api.get("/clients") or {}).get("clients", []):
            for g in c.get("guestFiles", []):
                acct = (g.get("accountName") or "").lower()
                if acct in GENERIC:
                    report("FAIL" if "guest" in acct else "REVIEW", "Connected now",
                           f"{c.get('ipaddress')} has {g.get('filename')} open as '{g.get('accountName')}'")

        roles = api.get("/server/adminrole")
        if isinstance(roles, list) or isinstance(roles, dict):
            n = len(roles if isinstance(roles, list) else roles.get("adminRoles", roles.get("roles", [])))
            report("PASS" if n else "REVIEW", "Admin roles",
                   f"{n} administrator role(s) defined" if n else
                   "no administrator roles: everyone shares the one Admin Console account")

        sch = (api.get("/schedules") or {}).get("schedules", [])
        enabled = [s.get("name") for s in sch if s.get("enabled")]
        if enabled:
            report("INFO", "Schedules", f"{len(enabled)} enabled: {', '.join(map(str, enabled[:10]))}; "
                   "confirm each is expected")
        plugins = [p.get("pluginName") or p.get("filename") for p in
                   (api.get("/plugins") or {}).get("plugins", []) if p.get("enabled")]
        if plugins:
            report("INFO", "Plug-ins", f"enabled: {', '.join(map(str, plugins))}")
    finally:
        try:
            api.call("DELETE", f"/user/auth/{api.token}")
        except (RuntimeError, OSError):
            print("  (sign-out failed; the token expires on its own after 15 minutes idle)")

    fails = sum(1 for r in results if r[0] == "FAIL")
    reviews = sum(1 for r in results if r[0] == "REVIEW")
    print(f"\n{fails} FAIL, {reviews} REVIEW. Not covered by the Admin API: Deny Guest and auto-login "
          "(fmsadmin get serverprefs DenyGuestAndAutoLogin), firewall rules, and accounts inside each file.")


if __name__ == "__main__":
    main()
