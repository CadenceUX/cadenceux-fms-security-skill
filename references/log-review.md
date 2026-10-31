# Log review

## Contents
- Which logs to collect
- Running the log check
- Reading each section
- Identifying addresses
- Verdicts
- How often to check

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
For routine checks, use the last check's end time. Without code execution, give the user both
commands and ask for the output.

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

**Failed FileMaker sign-ins.** The password-spraying signature is one address failing across
several accounts or files. Flags:

| Flag | Meaning | Weight |
|---|---|---|
| `NEVER-SUCCEEDED` | Address failed and never signed in, before or during the window | High when combined with any other flag |
| `MANY-ACCOUNTS` | 3+ different account names from one address | High |
| `MANY-FILES` | 3+ files from one address | High |
| `GENERIC/DEFAULT` | Blank, Admin, Guest, web, user, api, test, filemaker | High from an unknown address; often harmless from staff (a saved blank attempt before the real sign-in) |

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
| `BURST` | 100+ Data API or OData record calls, or 5+ layouts, from one address in 10 minutes |

TopCallStats keeps only the busiest calls, so real totals are higher than shown.

**Web server.** Requests to FileMaker paths and the busiest addresses. Internet scanning for
`.env`, WordPress or PHP paths that gets 404 is noise. A `200` from an unknown address on
`/fmi/data`, `/fmi/odata`, `/fmi/xml` or `/fmi/admin` is not.

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
