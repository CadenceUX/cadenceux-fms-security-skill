# Exposure check

What the internet can reach on the server. Facts from Claris's "Ports used by FileMaker
Server" (installation and configuration guide; KB 000026067), checked 2026-10-31.

## Contents
- Before running
- Ports
- Web paths
- Certificate
- Services and operating system
- Published issues for the services
- What can't be seen from outside
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
| 2399 open | Finding unless an external SQL client needs it; the attacks use it too. Where a BI or reporting tool needs ODBC/JDBC, allow 2399 only from that tool's addresses, never from anywhere. A web rate limiter or WAF doesn't cover it |
| 16000 open | Finding on 19.4 or later (it was the Admin Console port only up to 19.3). On a secondary machine it should be open only to the primary |
| 16001–16004, 1895, 5013, 8091, 50003, 50004, 3000, 8998, 9889, 9898, 16020, 16021 open | Finding: local-only ports reachable from outside mean the firewall isn't doing its job |
| 22, 3389, 5900, 5985/5986 open | Finding: remote management reachable from anywhere. Claris's checklist says to turn off Remote Desktop |
| Other remote access (23, 3283, 5901–5902, 5938) open | Finding: as above; Telnet (23) is unencrypted and should never answer |
| File sharing (21, 111, 135, 139, 445, 548, 873, 2049) open | Finding: file sharing belongs behind a VPN. FTP sends passwords unencrypted |
| A database (1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017) open | Finding: databases shouldn't answer the internet; Redis, Memcached, Elasticsearch and MongoDB often have no password by default |
| Mail ports open | Fine only on a mail server; otherwise a finding |
| Admin panels (2083, 2087, 8006, 9090, 10000, 9443) open | Finding unless allow-listed: each is a sign-in page for the whole machine |
| 5000 or 7000 open on a Mac | Finding: macOS's AirPlay Receiver, on by default. Turn it off on a server (System Settings > General > AirDrop & Handoff) |
| Docker or Kubernetes (2375, 2376, 6443, 10250) open | Critical for 2375 (anyone can run containers); finding for the rest |
| `filtered` | No answer; normal for a firewalled port |

The list is `references/ports.json`: 26 FileMaker and remote-management ports, then the common
services on Mac, Windows and Unix servers, 82 in all. Each port gets one TCP connection, a few at a
time with a pause between. TCP only: UDP services (DNS, SNMP, IPMI) aren't checked. Open and
filtered states come from a TCP connect; the script never sends FileMaker protocol traffic.

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
| `/fmi-test/phptest.php` | Not found. That doesn't prove PHP isn't installed: check on the server (server-config S15) | Answers, or any response whose `X-Powered-By` header names PHP: PHP is installed and reachable |
| `/fmi/webd/` | Not found if WebDirect is unused | WebDirect on when unused |
| Third-party admin tools (`/otto/` and similar) | Not reachable from outside | Sign-in page open to any address |
| `/` | A neutral page | The default page reveals that the server runs FileMaker Server; Claris's Security Guide suggests replacing it (low) |

## Certificate

The default certificate (issuer "Claris Root Authority", subject "Claris Test Certificate (Not
for Production Use)") is for testing only. A development CA (for example mkcert) shows as trusted
on the machine that installed it and untrusted everywhere else: fine for a local test server,
a finding on anything others connect to. Port 80 should answer only with a redirect to HTTPS. Production needs a trusted certificate; importing a
custom certificate also turns on HSTS. Note the expiry date in the report.

The check also reads the `Strict-Transport-Security` header (HSTS), and tries one TLS 1.0 and one
TLS 1.1 handshake on 443. Claris's Security Guide asks for current TLS only. A version the
scanning Mac's own TLS library can't offer is reported as not tested, never as refused, and a
server that closes the connection is reported as that, not as a clear refusal.

## Services and operating system

For every open port, `scripts/fms_service_scan.py` does what any client does before signing in,
once, and reports what the service gives away:

| Port | What's sent | What comes back |
|---|---|---|
| SSH, FTP, SMTP, POP3, IMAP, MySQL | Nothing: the service speaks first | Product and version; often a package revision (`OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`) that names the OS release |
| Web ports | One `GET /` | `Server` and `X-Powered-By` headers: nginx, Apache, IIS, PHP and their versions |
| VNC (5900–5902) | The VNC version reply | The security types offered. Apple's types or version `003.889` mean macOS Screen Sharing; type 1 means **no password at all** (Critical) |
| Remote Desktop (3389) | A connection request, then the first NTLM message of a sign-in | Whether Network Level Authentication is on, and the Windows version and computer and domain names the NTLM answer carries |
| SMB (445) | SMB 2 or 3 negotiation, then the same first NTLM message | The dialect, the Windows version and names. macOS and Samba answer with a placeholder (Windows 7, build 7600, or build 0): never read as Windows |
| FileMaker's ports | Nothing | Named from the port list; FileMaker shows no version before sign-in |

The NTLM exchange stops after the server's first answer: no account name or password is sent, and
Windows logs no failed sign-in. The computer and domain names it gives away are themselves a
finding (Low): they help an attacker aim a password spray.

**The OS line** weighs the evidence: a Windows build from NTLM first, then a package revision
(Ubuntu, Debian), then tags such as `(Ubuntu)` or AirPlay Receiver. Every piece of evidence is
listed. When services disagree (an Ubuntu web server in front of a Windows machine), the report
says so: a forwarder, container or second machine may answer some ports. FileMaker Server's own
version comes from `/fmi/data/vLatest/productInfo` when the Data API is on and the reply includes it.
FileMaker Server 26.0.3 leaves it out (checked 12 November 2026), so on current releases the version
needs a sign-in: the admin review reads it.

## Published issues for the services

Run with `--services-json <path>`, then pass that file to `scripts/fms_service_advisories.py`:

- **Ubuntu packages** (an SSH greeting with an `ubuntuN` revision, on 18.04, 20.04, 22.04 or 24.04)
  are checked against Ubuntu's own security data for that release: each CVE's fixed package
  version is compared with the installed one, the way dpkg compares them. This is exact. The data
  comes from OSV.dev, which carries Ubuntu's records and answers in one request (about 2 seconds);
  Ubuntu's own API is the fallback, at 20 CVEs a request and, on 12 November 2026, up to 50 seconds
  each. OSV gives CVSS as vectors; the first is Ubuntu's own, and its score is worked out by the CVSS 3.1
  formula. An unfixed issue Ubuntu rates negligible is left out, as Ubuntu's API leaves it out. A fix
  published only for Ubuntu Pro (ESM) is reported as that. Checked against Ubuntu's API on 13 November
  2026: the same 31 CVEs, fixes and scores for one OpenSSH package.
- **Anything else with a version** (OpenSSH, nginx, Apache, PHP, Exim, vsftpd, MySQL, MariaDB) is
  looked up on NVD by product and version, keeping only CVEs that list that version as vulnerable.
  A match means **this version is affected**, not that the server can be exploited: many apply only
  when a module or option is on (Apache's mod_ldap, OpenSSH's GSSAPI), which can't be seen from outside.
- **Distribution builds without a revision** (`nginx/1.24.0 (Ubuntu)`, `Apache/2.4.58 (Debian)`,
  IIS) aren't matched: they're patched without the version changing, so the version can't show
  whether they're up to date. Debian SSH packages are matched by upstream version with that caveat.
- **Operating system support** comes from `references/os-lifecycle.json`: a Windows release, Ubuntu
  LTS or Debian release past its end gets no security fixes at all (High). Ubuntu past standard
  support is fine only with Ubuntu Pro attached.

Only product names, versions and package names leave the scanning machine, never a hostname or an
address.

## What can't be seen from outside

The operating system's patch level, the kernel, and anything behind a sign-in. A kernel bug in the
TCP stack is reachable from outside, but nothing a server shows before sign-in says whether it's
patched, so neither this scan nor an attacker can tell without trying the exploit. The scan never
tries. When the user asks about a specific OS or kernel CVE, say so plainly, check the vendor's
page for that CVE (Ubuntu's CVE tracker, Microsoft's update guide) and point to the server's own
updates (unattended-upgrades, Windows Update, Software Update).

## Severity

| Severity | Examples |
|---|---|
| Critical | File names listed without sign-in on a server whose files use Guest or auto-login; local-only ports open; VNC asking for no password; Docker API (2375) open; a published issue CVSS 9 or above in a reachable service |
| High | HTTPS accepts TLS 1.0 or 1.1; Admin Console or third-party admin tool sign-in open to any address; 2399 open and unused, or open to any address while in use; PHP answering from outside; remote management ports open; Remote Desktop without Network Level Authentication; default certificate; a database answering the internet; an operating system out of support; a published issue CVSS 7 to 8.9 |
| Medium | HSTS off; Data API, OData, XML or WebDirect answering when unused; 443 or 5003 not allow-listed where clients are known; other open ports nothing intended needs; published issues below CVSS 7 |
| Low | Default FileMaker Server web page; a service giving away its version, computer or domain name |

## If the script can't be run

Give the user these to run from an outside connection and paste back:

```bash
nc -vz -w 4 <host> 5003
curl -sk -o /dev/null -w "%{http_code}\n" https://<host>/admin-console/
curl -sk https://<host>/fmi/data/vLatest/databases
curl -sk https://<host>/fmi/odata/v4
```

Or ask them to try a free online port checker for 2399, 16000 and 16001.
