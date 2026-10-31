# Exposure check

What the internet can reach on the server. Facts from Claris's "Ports used by FileMaker
Server" (installation and configuration guide; KB 000026067), checked 2026-10-31.

## Contents
- Before running
- Ports
- Web paths
- Certificate
- Severity
- If the script can't be run

## Before running

- Authorisation confirmed in intake. Hosting providers may also require notice before any
  scan; the script's connection checks are light, but say so if the user is unsure.
- Run from **outside** the server's network (home broadband, a phone hotspot, a cloud shell).
  From inside the network or a VPN it shows what the firewall allows internally.
- Repeat from a second outside address if the user's office address is allow-listed; an
  allow-listed address sees more than the internet does.

## Ports

Only four ports should ever be open on a single-machine server, and only for the services in
use: **80** (redirect to HTTPS), **443** (Admin Console, Data API, OData, XML, WebDirect),
**5003** (FileMaker Pro and Go), **2399** (ODBC/JDBC). Everything else FileMaker Server uses is
local only and must not answer from outside.

| Result | Judgement |
|---|---|
| 443 open | Expected if any web service or the Admin Console is used. Prefer an IP allow-list or VPN, especially when the Data API or OData is on |
| 5003 open | Expected if remote FileMaker Pro or Go clients connect. Prefer an IP allow-list or VPN |
| 80 open | Fine if it only redirects to HTTPS |
| 2399 open | Finding unless an external SQL client needs it; the attacks use it too |
| 16000 open | Finding on 19.4 or later (it was the Admin Console port only up to 19.3). On a secondary machine it should be open only to the primary |
| 16001–16004, 1895, 5013, 8091, 50003, 50004, 3000, 8998, 9889, 9898, 16020, 16021 open | Finding: local-only ports reachable from outside mean the firewall isn't doing its job |
| 22, 3389, 5900, 5985/5986 open | Finding: remote management reachable from anywhere. Claris's checklist says to turn off Remote Desktop |
| `filtered` | No answer; normal for a firewalled port |

Open and filtered states come from a TCP connect only; the script never sends FileMaker
protocol traffic.

**Port forwarders can show ports as open that nothing is listening on.** Docker Desktop (and
some load balancers and NAT devices) accept the connection on every published port and only
then try the server. Before reporting an open port as a running service, confirm it with the
service's own setting (the admin review shows whether ODBC/JDBC is enabled) or with the
listeners on the server (`ss -ltn` on Linux, or `docker exec <container> ss -ltn`).

## Web paths

| Path | Healthy result | Finding |
|---|---|---|
| `/admin-console/` | Not reachable, or reachable only from allowed addresses | Sign-in page open to any address: restrict access by IP (Administration > Restrict Access) or VPN |
| `/fmi/admin/api/v2/...` | Refuses without a token | Any data without a token |
| `/fmi/data/vLatest/productInfo` | 502/503 if the Data API is off | Answering when the Data API isn't meant to be used |
| `/fmi/data/vLatest/databases` | No file names | **File names listed without sign-in.** The attack tools start here. Filter databases alone doesn't close this: the Data API file list needs credentials only when Filter databases **and** `DenyGuestAndAutoLogin` are both on |
| `/fmi/odata/v4` | Empty list without credentials | File names listed |
| `/fmi/xml/fmresultset.xml?-dbnames` | Error 959 (XML publishing off) | File names listed, or XML on when unused |
| `/fmi/webd/` | Not found if WebDirect is unused | WebDirect on when unused |
| Third-party admin tools (`/otto/` and similar) | Not reachable from outside | Sign-in page open to any address |
| `/` | A neutral page | The default page reveals that the server runs FileMaker Server; Claris's Security Guide suggests replacing it (low) |

## Certificate

The default certificate (issuer "Claris Root Authority", subject "Claris Test Certificate (Not
for Production Use)") is for testing only. A development CA (for example mkcert) shows as trusted
on the machine that installed it and untrusted everywhere else: fine for a local test server,
a finding on anything others connect to. Port 80 should answer only with a redirect to HTTPS. Production needs a trusted certificate; importing a
custom certificate also turns on HSTS. Note the expiry date in the report.

## Severity

| Severity | Examples |
|---|---|
| Critical | File names listed without sign-in on a server whose files use Guest or auto-login; local-only ports open |
| High | Admin Console or third-party admin tool sign-in open to any address; 2399 open and unused; remote management ports open; default certificate |
| Medium | Data API, OData, XML or WebDirect answering when unused; 443 or 5003 not allow-listed where clients are known |
| Low | Default FileMaker Server web page |

## If the script can't be run

Give the user these to run from an outside connection and paste back:

```bash
nc -vz -w 4 <host> 5003
curl -sk -o /dev/null -w "%{http_code}\n" https://<host>/admin-console/
curl -sk https://<host>/fmi/data/vLatest/databases
curl -sk https://<host>/fmi/odata/v4
```

Or ask them to try a free online port checker for 2399, 16000 and 16001.
