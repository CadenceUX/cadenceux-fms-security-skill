#!/usr/bin/env python3
"""FMS exposure check: what a FileMaker Server shows to the internet.

Run it from OUTSIDE the server's network (home connection, phone hotspot, cloud
shell), against a server you own or are authorised to test. It:

  * tries a TCP connection to each port in references/ports.json: FileMaker's, then the
    common services on Mac, Windows and Unix servers (remote access, file sharing,
    databases, mail, admin panels)
  * reads the TLS certificate on 443 (issuer, expiry, name match)
  * requests the FileMaker web paths without credentials and reports the status,
    whether they return hosted file names, and whether port 80 redirects to HTTPS
  * asks each open port what it is (fms_service_scan.py): the product and version a
    service gives away before sign-in, and the operating system where one names it
  * reads FileMaker Server's version from the Data API's product information, which
    answers without sign-in when the Data API is on

Read-only and polite: no passwords, no account names, no exploits, one request
per path, a pause between connections, at most a few connections at once. Uses
only the Python standard library.

Usage:
    python3 fms_exposure_check.py <hostname> [--ports-only | --web-only] [--services-json <path>]

--services-json writes the services, the operating system and the FileMaker Server
version as JSON, for fms_service_advisories.py.
"""
import concurrent.futures
import http.client
import importlib.util
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 4       # seconds per connection; long enough for a distant server, short enough to finish quickly
PAUSE = 0.3       # seconds between connections, so the check doesn't look like a flood to an IDS
WORKERS = 8       # ports tried at once: a firewalled port waits the full TIMEOUT, so 80-odd one at a time would take minutes
HERE = os.path.dirname(os.path.abspath(__file__))
LIFECYCLE_FILE = os.path.join(HERE, "..", "references", "os-lifecycle.json")


def load_module(name):
    """A sibling script, loaded by path: a program may start this one with python3 -I, which leaves its folder off sys.path."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_lifecycle():
    try:
        with open(LIFECYCLE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

# The ports to try, in order, from references/ports.json: port, group, what uses it, and whether it should
# answer from the internet. The FileMaker ones are from Claris's "Ports used by FileMaker Server" (installation
# guide and KB 000026067). The scanner file shows the same list, so the two can't drift apart.
PORTS_FILE = os.path.join(HERE, "..", "references", "ports.json")


def load_ports(path=PORTS_FILE):
    try:
        with open(path, encoding="utf-8") as f:
            return {p["port"]: (p["what"], p["expect"]) for p in json.load(f)["ports"]}
    except (OSError, ValueError, KeyError, TypeError) as e:
        sys.exit(f"Can't read the port list at {path}: {e}")


PORTS = load_ports()

# path: what it is. Requested with GET and no credentials.
PATHS = {
    "/": "Default web page",
    "/admin-console/": "Admin Console sign-in page",
    "/fmi/admin/api/v2/server/metadata": "Admin API (should refuse without a token)",
    "/fmi/data/vLatest/productInfo": "Data API product information",
    "/fmi/data/vLatest/databases": "Data API hosted file list",
    "/fmi/odata/v4": "OData service document (hosted file list)",
    "/fmi/xml/fmresultset.xml?-dbnames": "XML Custom Web Publishing file list",
    "/fmi/webd/": "WebDirect launch centre",
    "/fmi-test/phptest.php": "PHP test page (FileMaker Server's own, from when it bundled PHP)",
    "/otto/": "OttoFMS console (third-party admin tool)",
}


def tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return "OPEN"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        return f"error ({e.strerror or e})"


def probe(host, port):
    state = tcp(host, port)
    time.sleep(PAUSE)
    return state


def fms_version(body):
    """FileMaker Server's version from the Data API's productInfo reply, or empty."""
    try:
        info = (json.loads(body).get("response") or {}).get("productInfo") or {}
    except (ValueError, AttributeError):
        return ""
    v = str(info.get("version") or "")
    return v if re.fullmatch(r"\d+(?:\.\d+){1,3}", v) else ""


def certificate(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
            issuer = dict(x[0] for x in c.get("issuer", ()))
            name = issuer.get("organizationName", issuer.get("commonName", "?"))
            local = "  <-- a development CA: trusted only on machines that installed it" \
                if re.search(r"mkcert|development|local", name, re.I) else ""
            return f"trusted here; issuer {name}; expires {c.get('notAfter')}; protocol {t.version()}{local}"
    except ssl.SSLCertVerificationError as e:
        return f"NOT TRUSTED ({e.verify_message}). A self-signed or default certificate lets clients be intercepted"
    except (OSError, ssl.SSLError) as e:
        return f"could not read ({e})"


def hsts(host):
    """Whether HTTPS answers with Strict-Transport-Security. Claris turns it on with a custom certificate."""
    try:
        conn = http.client.HTTPSConnection(host, 443, timeout=TIMEOUT, context=ssl.create_default_context())
        conn.request("GET", "/", headers={"User-Agent": "fms-exposure-check"})
        r = conn.getresponse()
        value = r.getheader("Strict-Transport-Security")
        r.read()
        conn.close()
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        return f"could not read ({e})"
    return f"on ({value})" if value else "OFF: no Strict-Transport-Security header  <-- turn on HSTS"


def old_tls(host, port=443):
    """Try one TLS 1.0 and one TLS 1.1 handshake. A server that accepts either lets a client be pushed to weak
    encryption. A version this Mac's own TLS library can't offer is reported as not tested, never as refused."""
    accepted, refused, dropped, untested = [], [], [], []
    for name, version in (("1.0", ssl.TLSVersion.TLSv1), ("1.1", ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            # OpenSSL 3 and later refuse old TLS at the default security level; LibreSSL (macOS's own Python) has
            # no levels, rejects the setting and offers old TLS anyway
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            ctx.minimum_version = ctx.maximum_version = version
        except (ValueError, ssl.SSLError):
            untested.append(name)
            continue
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host):
                accepted.append(name)
        except ssl.SSLError as e:
            (untested if "NO_PROTOCOLS_AVAILABLE" in str(e) or "no protocols available" in str(e) else refused).append(name)
        except OSError:
            dropped.append(name)   # the server closed the connection: most likely a refusal, but not a clear one
    parts = ([f"ACCEPTS TLS {' and '.join(accepted)}"] if accepted else []) + \
            ([f"refuses TLS {' and '.join(refused)}"] if refused else []) + \
            ([f"closed the connection on TLS {' and '.join(dropped)}"] if dropped else []) + \
            ([f"TLS {' and '.join(untested)} not tested (this Mac can't offer it)"] if untested else [])
    return "; ".join(parts) + ("  <-- turn off TLS 1.0 and 1.1" if accepted else "")


def server_header(headers):
    """The Server header, plus X-Powered-By when a page admits to PHP or anything else."""
    powered = headers.get("X-Powered-By", "")
    return headers.get("Server", "") + (f" X-Powered-By: {powered}" if powered else "")


def fetch(host, path):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # the certificate is judged separately above
    req = urllib.request.Request(f"https://{host}{path}", headers={"User-Agent": "fms-exposure-check"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status, server_header(r.headers), r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, server_header(e.headers), e.read(20000).decode("utf-8", "replace")
    except (OSError, ssl.SSLError) as e:
        return None, "", str(e)


def http_redirect(host):
    """Report what plain HTTP on port 80 does with a request for /."""
    conn = http.client.HTTPConnection(host, 80, timeout=TIMEOUT)
    try:
        conn.request("GET", "/", headers={"User-Agent": "fms-exposure-check"})
        r = conn.getresponse()
        where = r.getheader("Location", "")
        if r.status in (301, 302, 307, 308) and where.startswith("https://"):
            return f"{r.status}, redirects to HTTPS (ok)"
        return f"{r.status} {where}  <-- serves content over plain HTTP; redirect it to HTTPS"
    except OSError as e:
        return f"no answer ({e})"
    finally:
        conn.close()


def file_names(path, body):
    """Return hosted file names if the response lists any."""
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        dbs = (data.get("response") or {}).get("databases") if "response" in data else None
        if dbs:
            return [d.get("name") for d in dbs if isinstance(d, dict)]
        if "value" in data and isinstance(data["value"], list):
            return [v.get("name") for v in data["value"] if isinstance(v, dict)]
    if "-dbnames" in path:
        return re.findall(r'<data>([^<]+)</data>', body)
    return []


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    host = sys.argv[1].replace("https://", "").replace("http://", "").strip("/")
    args = sys.argv[2:]
    mode = next((a for a in args if a in ("--ports-only", "--web-only")), "")
    json_out = args[args.index("--services-json") + 1] if "--services-json" in args[:-1] else ""
    try:
        print(f"##### FMS exposure check: {host} ({socket.gethostbyname(host)})")
    except OSError as e:
        sys.exit(f"Cannot resolve {host}: {e}")

    open_ports = []
    if mode != "--web-only":
        print("\n## Ports (TCP connect only)")
        # A few at a time, printed in list order as each one's answer arrives
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            tried = [(port, what, expect, pool.submit(probe, host, port)) for port, (what, expect) in PORTS.items()]
            for port, what, expect, future in tried:
                state = future.result()
                flag = "  <-- review" if state == "OPEN" and expect.startswith(("should", "close")) else ""
                print(f"  {port:<6} {state:10} {what}  [{expect}]{flag}", flush=True)
                if state == "OPEN":
                    open_ports.append(port)
    if mode == "--ports-only":
        return

    print(f"\n## HTTP (80): {http_redirect(host)}")
    print(f"## Certificate (443): {certificate(host)}")
    print(f"## HSTS (443): {hsts(host)}")
    print(f"## Old TLS (443): {old_tls(host)}")
    print("\n## Web paths (GET, no credentials)")
    version = ""
    for path, what in PATHS.items():
        status, server, body = fetch(host, path)
        if status == 200 and "productInfo" in path:
            version = fms_version(body)
        names = file_names(path, body) if status == 200 else []
        note = ""
        xml_error = re.search(r'<error code="(\d+)"', body) if "-dbnames" in path else None
        if names:
            note = f"  <-- LISTS {len(names)} FILES WITHOUT SIGN-IN: {', '.join(names[:5])}"
        elif xml_error:
            code = xml_error.group(1)
            note = "  XML publishing is off (error 959)" if code == "959" else \
                f"  <-- XML publishing is ON (error {code}), no files listed; turn it off if unused"
        elif status == 200 and path in ("/fmi/odata/v4", "/fmi/data/vLatest/databases"):
            note = "  answers, but lists no files without credentials"
        elif status == 200 and path == "/" and re.search(r"FileMaker", body):
            note = "  default FileMaker Server page: shows the product to anyone (replace it)"
        elif status == 200 and "productInfo" in path:
            note = "  Data API is on"
        elif status == 200 and path in ("/admin-console/", "/otto/"):
            note = "  <-- sign-in page open to any address"
        elif status == 200 and "-dbnames" in path:
            note = "  <-- XML publishing answers; turn it off if unused"
        elif status == 200 and "phptest" in path:
            note = "  <-- PHP answers: find its version on the server, then patch or remove it"
        elif status and "phptest" in path:
            note = "  no PHP test page; this doesn't prove PHP isn't installed, so check on the server"
        elif status in (502, 503):
            note = "  service not running behind the web server"
        print(f"  {str(status or '-'):5} {path:40} {what}{note}")
        if server and (path == "/" or "X-Powered-By" in server):
            php = "  <-- names PHP: patch or remove it" if re.search(r"X-Powered-By:.*PHP", server, re.I) else ""
            print(f"        Server header: {server}{php}")
        time.sleep(PAUSE)

    print(f"\n## FileMaker Server version (no sign-in): "
          + (f"{version} (from the Data API's product information)" if version else
             "not shown (the Data API's product information has no version, as on FileMaker Server 26, or didn't answer)"))
    services, system = [], {}
    if mode != "--web-only":
        svc, lifecycle = load_module("fms_service_scan"), load_lifecycle()
        print("\n## Services (what each open port says, no sign-in)")
        if not open_ports:
            print("  no open ports to ask")
        for port in open_ports:
            found = svc.identify(host, port, PORTS[port][0], lifecycle)
            for s in found if isinstance(found, list) else [found]:
                services.append(s)
                print(f"  {port:<6} {svc.describe(s)}", flush=True)
            time.sleep(PAUSE)
        system = svc.best_os(services)
        if system["name"]:
            line = svc.os_label(system["name"], system["release"])
            print(f"\n## OS (from what the services say): {line} ({'; '.join(system['evidence'])})")
            if not system["agree"]:
                print(f"   Other services name {', '.join(system['others'])}: a forwarder, container or second machine may "
                      "answer some ports")
        else:
            print("\n## OS (from what the services say): not identified (no open service names one)")
    print("## Not visible from outside: the operating system's patch level, kernel bugs, and bugs that need a sign-in "
          "first. Nobody outside can see these, attackers included; keep the server's own updates on.")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({"host": host, "checked": time.strftime("%Y-%m-%d %H:%M:%S"), "fms_version": version,
                       "services": services, "os": system, "open_ports": open_ports}, f, indent=1)


if __name__ == "__main__":
    main()
