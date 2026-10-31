#!/usr/bin/env python3
"""FMS exposure check: what a FileMaker Server shows to the internet.

Run it from OUTSIDE the server's network (home connection, phone hotspot, cloud
shell), against a server you own or are authorised to test. It:

  * tries a TCP connection to each FileMaker and common admin port
  * reads the TLS certificate on 443 (issuer, expiry, name match)
  * requests the FileMaker web paths without credentials and reports the status,
    whether they return hosted file names, and whether port 80 redirects to HTTPS

Read-only and polite: no passwords, no account names, no exploits, one request
per path, a pause between connections. Uses only the Python standard library.

Usage:
    python3 fms_exposure_check.py <hostname> [--ports-only | --web-only]
"""
import http.client
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 4       # seconds per connection; long enough for a distant server, short enough to finish quickly
PAUSE = 0.3       # seconds between connections, so the check doesn't look like a flood to an IDS

# port: (what uses it, whether it should answer from the internet). From Claris's
# "Ports used by FileMaker Server" (installation guide and KB 000026067), checked 2026-10-31.
PORTS = {
    80: ("HTTP (should only redirect to HTTPS)", "ok"),
    443: ("HTTPS: WebDirect, Data API, OData, XML, Admin Console, Admin API", "ok if used; restrict by IP where possible"),
    5003: ("FileMaker Pro and Go clients", "ok if remote clients need it; restrict by IP or VPN where possible"),
    2399: ("ODBC/JDBC", "close unless an external SQL client needs it"),
    16000: ("Admin Console in 19.3 and earlier; secondary-machine traffic", "should be closed on 19.4+"),
    16001: ("Admin Console, local only", "should be closed"),
    16002: ("Admin server, local only from 19.5.1", "should be closed"),
    16003: ("Web Publishing Engine (open only on a secondary machine, to the primary)", "should be closed"),
    16004: ("Database Server, local only", "should be closed"),
    1895: ("Database Server, local only", "should be closed"),
    5013: ("Database Server, local only", "should be closed"),
    8091: ("WebSocket tunnelling, local only (2024+)", "should be closed"),
    50003: ("FileMaker Server service, local only", "should be closed"),
    50004: ("FileMaker Script Engine, local only", "should be closed"),
    3000: ("Web Publishing Engine, local only", "should be closed"),
    8998: ("Web Publishing Engine, local only", "should be closed"),
    9889: ("Web Publishing Engine, local only", "should be closed"),
    9898: ("Web Publishing Engine, local only", "should be closed"),
    16020: ("Web Publishing Engine, local only", "should be closed"),
    16021: ("Web Publishing Engine, local only", "should be closed"),
    10050: ("Zabbix monitoring agent", "close unless a monitoring server needs it, then restrict by IP"),
    22: ("SSH", "close or restrict by IP"),
    3389: ("Windows Remote Desktop", "close or restrict by IP or VPN"),
    5900: ("macOS Screen Sharing / VNC", "close or restrict by IP or VPN"),
    5985: ("Windows Remote Management (HTTP)", "should be closed"),
    5986: ("Windows Remote Management (HTTPS)", "should be closed"),
}

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


def fetch(host, path):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # the certificate is judged separately above
    req = urllib.request.Request(f"https://{host}{path}", headers={"User-Agent": "fms-exposure-check"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status, r.headers.get("Server", ""), r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Server", ""), e.read(20000).decode("utf-8", "replace")
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
    mode = sys.argv[2] if len(sys.argv) > 2 else ""
    try:
        print(f"##### FMS exposure check: {host} ({socket.gethostbyname(host)})")
    except OSError as e:
        sys.exit(f"Cannot resolve {host}: {e}")

    if mode != "--web-only":
        print("\n## Ports (TCP connect only)")
        for port, (what, expect) in PORTS.items():
            state = tcp(host, port)
            flag = "  <-- review" if state == "OPEN" and expect.startswith(("should", "close")) else ""
            print(f"  {port:<6} {state:10} {what}  [{expect}]{flag}")
            time.sleep(PAUSE)
    if mode == "--ports-only":
        return

    print(f"\n## HTTP (80): {http_redirect(host)}")
    print(f"## Certificate (443): {certificate(host)}")
    print("\n## Web paths (GET, no credentials)")
    for path, what in PATHS.items():
        status, server, body = fetch(host, path)
        names = file_names(path, body) if status == 200 else []
        note = ""
        xml_error = re.search(r'<error code="(\d+)"', body) if "-dbnames" in path else None
        if names:
            note = f"  <-- LISTS {len(names)} FILES WITHOUT SIGN-IN: {', '.join(names[:5])}"
        elif xml_error:
            code = xml_error.group(1)
            note = "  XML publishing is off (error 959)" if code == "959" else f"  FileMaker error {code}, no files listed"
        elif status == 200 and path in ("/fmi/odata/v4", "/fmi/data/vLatest/databases"):
            note = "  answers, but lists no files without credentials"
        elif status == 200 and path == "/" and re.search(r"FileMaker", body):
            note = "  default FileMaker Server page: shows the product to anyone (replace it)"
        elif status == 200 and "productInfo" in path:
            note = "  Data API is on"
        elif status == 200 and path in ("/admin-console/", "/otto/"):
            note = "  <-- sign-in page open to any address"
        elif status in (502, 503):
            note = "  service not running behind the web server"
        print(f"  {str(status or '-'):5} {path:40} {what}{note}")
        if server and path == "/":
            print(f"        Server header: {server}")
        time.sleep(PAUSE)


if __name__ == "__main__":
    main()
