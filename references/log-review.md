# Log review

## Contents
- What the automated attacks do
- Which logs to collect
- Running the log check
- Reading each section
- Identifying addresses
- Verdicts
- How often to check

## What the automated attacks do

The pattern Claris described (support.claris.com, KB 000049228, "Protecting FileMaker Server
from automated attacks") and that the log check looks for:

1. Ask the server for its hosted file list through the web APIs (it needs no sign-in unless
   Filter databases and Deny Guest and auto-login are both on).
2. Open each file through Guest, auto-login, or a default Admin account with no password.
3. Spray common passwords at generic account names, a few tries at a time from rotating
   addresses, through ODBC/JDBC on port 2399 as well as 443. FileMaker locks a file account for
   five minutes after five failed sign-ins within five minutes, and spraying stays under that.
4. Once in, pull records through the Data API, 200 at a time, across every layout available.

No FileMaker Server flaw is involved: every step works through configuration. Steps 2 and 4
leave no failed sign-in, which is why the log review checks downloads as well as failures.

## Which logs to collect

Collect the whole Logs folder from the server (zip it), not single files. The check needs
Access.log and Event.log; everything else adds evidence. Copy the files rather than opening
them in place.

| Platform | Logs folder |
|---|---|
| Linux | `/opt/FileMaker/FileMaker Server/Logs` |
| macOS | `/Library/FileMaker Server/Logs` |
| Windows | `[drive]:\Program Files\FileMaker\FileMaker Server\Logs` |

In a multi-machine deployment the logs are on the primary. **fac.log is not in Logs**: it is in
`FileMaker Server/Admin/FAC/logs/`. The web-server access log is the web server's own. On Linux
FileMaker Server's nginx writes `FileMaker Server/NginxServer/logs/nginx-access.log` and rotates
it daily into dated files (`nginx-access.log-YYYY-MM-DD`, older ones gzipped): collect those too.
On Windows it is IIS, on macOS Apache; if the user can't find it, ask the hosting provider.
FileMaker Server in Docker: copy the folders out with `docker cp <container>:"<path>" <dest>`.

| Log | What it adds | Notes |
|---|---|---|
| Access.log (+ Access-old.log) | Every connection: address, machine name, client, account, file | Rolls over by size; on a busy server it can cover only a couple of weeks |
| Event.log | Failed sign-ins per file and account, Admin Console sign-ins, settings changes, uploads, schedules | |
| fac.log | Admin API activity and errors | Calls through the web server show as 127.0.0.1 |
| TopCallStats.log | Record reads and downloads per client | **Off by default.** Turn on Top Call Statistics in Logs > Log Settings. It keeps only the 25 slowest calls per interval |
| Web-server access log (nginx or IIS) | Data API, OData, XML, WebDirect and Admin Console requests, with status codes | Often keeps only the current day. Missing days are unknown, not clean |
| fmdapi.log, fmodata.log | Data API and OData errors | Useful when the web-server log has rolled |

Ask the user to pull logs **before** restarting or upgrading the server, and to copy them off
the server at least daily while a review is open.

## Running the log check

Run `scripts/fms_logcheck.py` on the zip or folder. With no time given it covers the 24 hours
before the newest Access.log entry; pass a start time to cover longer:

```bash
python3 scripts/fms_logcheck.py ~/Downloads/server-logs.zip
python3 scripts/fms_logcheck.py ~/Downloads/server-logs.zip "2026-10-15 00:00"
```

For a first review, start from the earliest date the logs hold, so every address is judged.
For routine checks, use the last check's end time. `fms_scan.py` runs it over everything the logs
hold, with `--brief` (the busiest and new connections, the failed sign-ins that matter most, counts
for the rest) and the full output saved as `logcheck.txt`. Run it alone with `--brief` too, unless
a section's full list is needed.

## Reading each section

**Connections.** Every address in the window, with machine name, client and account. `NEW`
means the address never appeared before the window. A new address alone is not a finding; a
new address with a new machine name, an old client version, or a generic account is. On a first
review that starts at the earliest log entry there is nothing to compare with, so nothing is
marked `NEW`; judge every address with the user instead.

If every address is private (the script says so), the server sits behind NAT, a proxy, a load
balancer or a container gateway (Docker Desktop shows every client as its gateway address). The
FileMaker logs then can't tell clients apart by address: identify them by machine name and
account, and get real addresses from the edge firewall or proxy logs. Say this in the report.

**Client versions.** Each FileMaker Pro and Go build that connected, with the machines that
used it. `UPDATE` marks a Pro build with a published issue (from `security-advisories.md`);
these are client-side and go in the report's "clients to update" section. Very old builds also
point to machines nobody maintains.

**Failed FileMaker sign-ins.** The check reads Event.log and Event-old.log. The password-spraying
signature is one address failing across several accounts or files. Flags:

| Flag | Meaning | Weight |
|---|---|---|
| `POSSIBLE-COMPROMISE` | The address failed and also signed in, and either the sign-in was over ODBC/JDBC or as a generic account, or it's a `NEW` address that tried 3+ account names | Stop and confirm who it is today. Unconfirmed, go to `incident-response.md` |
| `SIGNED-IN` | The address failed and also signed in, with the account, time and connection type. A success counts **before or after** the failures | Check, don't assume. One or two failures, then a sign-in as the same person's own account, is usually staff mistyping. Confirm the address with the user |
| `NEVER-SUCCEEDED` | Address failed and never signed in, in the Access logs supplied | High when combined with any other flag |
| `BEFORE-ACCESS-LOG` | The failures are older than the Access log, so a sign-in can't be ruled out | A limit on the verdict, never a pass |
| `MANY-ACCOUNTS` | 3+ different account names from one address | High |
| `MANY-FILES` | 3+ files from one address | High |
| `GENERIC/DEFAULT` | Blank, Admin, Guest, web, user, api, test, filemaker | High from an unknown address; often harmless from staff (a saved blank attempt before the real sign-in) |
| `RATE` | 20+ failures from one address in 10 minutes | High across several account names. On one name, usually a person or a saved password retrying |
| `SERVER-ITSELF` | The failure came from 127.0.0.1: the client name is usually a script or schedule | Not an attack in itself, but a schedule with a stale password shouldn't be failing. Find it and fix it |
| `XDBC` | The failure came through ODBC/JDBC (`[fmxdbc]`, port 2399) | High from an unknown address: the attacks spray 2399 as well as 443. From a known SQL or BI tool, a daily failure usually means a stale stored password |

Then the breach test: a success at any time, **before or after** the failures, from an address
the user doesn't recognise is possible compromise until they confirm it. Attackers sign in with
what works, then go on trying other accounts and files. Check Access.log and the Data API and
OData logs for when, and as which account.

An account name shown as hidden may be a password typed into the account box. Have that person
change the password, and don't copy the log line into a report.

A low failure count per account is not reassurance. FileMaker locks a file account for five
minutes after five failed sign-ins within five minutes, and spraying stays under that; group the
failures by address and by account name together. The defences are strong unique passwords,
allow-listing 443 and 2399 or a VPN, and a rate limiter or WAF (server-config.md). A web rate limiter or
WAF doesn't see port 2399: when `XDBC` failures appear, close 2399 at the firewall, or allow it
only from the SQL or BI tools' own addresses.

**ODBC/JDBC connections.** Every connection through port 2399 in the window, whether or not
anything failed, because an attacker who gets in first time leaves no failure. Each address should
match a SQL or BI tool the user can name. An unknown address here is possible compromise, and a
`GENERIC` account makes it worse.

**Admin Console sign-ins.** Every admin sign-in with address and account. Any admin sign-in or
failure from a `NEW` address needs the user to confirm it the same day. `GENERIC` means the
Admin Console account has a guessable name such as admin: a finding (server-config S3). A daily failure from the
same address usually means a management tool or hosting provider still holds an old password.

**Security, settings and file events.** Uploads, removals, schedule changes and setting
changes. Each should match a planned change or deployment.

**Admin API errors.** Repeated auth errors usually mean a tool with stale credentials.

**Record downloads.** Files with Guest or auto-login sign in without a single failure, so the
failed sign-in section misses them. This section looks for volume instead:

| Flag | Meaning |
|---|---|
| `HIGH-VOLUME` | 20+ MB to one client in 10 minutes (normal peaks are a few MB) |
| `WIDE` | 40+ tables in 10 minutes from a `NEW` address or a Guest or generic account. Developers routinely reach 60+ tables, so width alone is not flagged |
| `BURST` | 100+ Data API, OData or XML record calls, or 5+ layouts, from one address in 10 minutes |

TopCallStats keeps only the busiest calls, so real totals are higher than shown.

**Web server.** Requests to FileMaker paths and the busiest addresses. Internet scanning for
`.env`, WordPress or PHP paths that gets 404 is noise. A `200` from an unknown address on
`/fmi/data`, `/fmi/odata`, `/fmi/xml` or `/fmi/admin` is not, and any line marked `ANSWERED` means a
PHP or XML path was served: check the server for PHP (server-config S15). Rotated
`nginx-access.log-YYYY-MM-DD` files are read too, gzipped or not. IIS and Apache logs aren't
parsed: read those by hand.

## Identifying addresses

Never guess who an address belongs to. For each address that matters:

1. Look up the network owner (whois, reverse DNS) to tell a home broadband or mobile carrier
   from a hosting provider or VPN. Hosting and VPN ranges carry most automated attacks.
2. Ask the user whether the machine name, account and network match a known person, office,
   integration, monitoring service or hosting provider. Record the answer and reuse it for the
   rest of the review.
3. Watch for staff connecting from somewhere unexpected (another customer's server, a shared
   machine). It isn't an attack, but the password has been typed on a machine nobody controls,
   so it belongs in the rotation list.

Keep known addresses in the report so the next check is quicker. Treat them as sensitive.

## Verdicts

Use one of three, and say which logs and dates the verdict rests on:

- **No sign of attack**: no flagged failures from unknown addresses, no unexplained downloads,
  and the logs cover the period asked about.
- **Attempted**: flagged failures from unknown addresses, but no successful sign-in or
  download from them.
- **Possible compromise**: an unknown address signed in, an unexplained download flag, or an
  admin action nobody can account for. Go to `incident-response.md`.

A gap in the logs (rolled web-server log, missing days) is stated as a limit on the verdict,
never treated as clean.

## How often to check

Until logs are shipped centrally with alerts:

| Server | How often |
|---|---|
| Internet-facing (WebDirect, Data API or OData reachable), and integration servers | Daily |
| Others | Weekly |
| Any | Same day after a security advisory, a password change, a deployment or an alert |

Once logs are central, alert in real time on: 20+ failed sign-ins from one address in 10
minutes; any Guest, blank, Admin or generic attempt from an unknown address; any admin sign-in
from an address not on the allowed list; any Data API or OData session from an unknown address.
Keep at least 90 days.
