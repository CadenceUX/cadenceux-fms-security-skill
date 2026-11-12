# Changelog

## [1.3.0] — 2026-11-13

A scan now costs far less of a usage limit, and sees what an attacker sees. One command runs every
automated check and prints a short summary instead of each check's full output; the skill reads a
reference only for the step at hand. The exposure check now covers every common service on a Mac,
Windows or Unix server, what each one gives away before sign-in, and the published issues for those
versions. No sign-in, no SSH account, no exploit.

### Token use

Before 1.3.0 a full scan of one server used about 5% of a weekly usage limit (8 November 2026). The
conversation carried every check's raw output, about 100 to 170 KB (81 KB from the log check alone
on a server with 288 addresses), and re-read it on every one of 25 to 40 turns.

- `scripts/fms_scan.py`: one command for the exposure check, services, published issues and the log
  review. Saves each full output, writes `findings.json` and `report-draft.md` (the report layout
  with what only the user can supply marked TODO), and prints a summary of about 5 KB. On a busy
  that replaced about 110 KB of check output.
- `scripts/fms_findings.py`: the code that turns check output into findings, shared with the FMS
  FileMaker solution that runs these checks without a model, so a finding reads the same in both. `references/finding-templates.json`
  gives each its priority, title, why and what to do.
- `scripts/fms_logcheck.py --brief` (the busiest and new connections, the failed sign-ins that matter
  most, counts for the rest) and `--save <file>` for the full output. 81 KB became 16 KB on a busy
  server. Without either flag the output is unchanged.
- `SKILL.md`: from 16 KB to 11 KB. A "Keep the context small" section; references read per step; the
  scripts table moved to `references/scripts.md` and the attack pattern to `references/log-review.md`.
- No published-issues list at intake: the version is looked up when the scan has it. The no-version
  list (3.8 KB) runs only when asked for.
- Without code execution, the user shares `summary.txt` and `report-draft.md` (about 15 KB) instead
  of every output.

### Added

- `references/ports.json`: 56 more ports (82 in all), grouped: remote access, file sharing,
  databases, mail, directory and DNS, web apps and admin panels, containers and monitoring,
  messaging and printing. The FileMaker 26 keep their order and wording.
- `scripts/fms_service_scan.py`, run by the exposure check on every open port: SSH, FTP, mail and
  MySQL greetings, web server headers, VNC security types (macOS Screen Sharing, no password),
  and the first NTLM answer from Remote Desktop and SMB (Windows build, NLA, names given away).
  macOS's and Samba's placeholder NTLM version is never read as Windows.
- `scripts/fms_exposure_check.py`: a `## Services` section, an `## OS` line with its evidence,
  FileMaker Server's version from the Data API's product information (no sign-in), a
  `## Not visible from outside` line, and `--services-json`.
- `scripts/fms_service_advisories.py`: Ubuntu SSH packages checked against Ubuntu's security data
  for their release (fixed package versions compared as dpkg does), through OSV.dev (one request,
  about 2 seconds) with Ubuntu's own API as the fallback; other versions against NVD by CPE, kept
  only when NVD lists the version as vulnerable; the operating system's support. Checked against
  Ubuntu's API on 13 November 2026: the same 31 CVEs, fixes and scores for one OpenSSH package.
- `references/os-lifecycle.json`: Windows builds, Ubuntu LTS and Debian releases with their support
  end dates, checked 12 November 2026.
- `scripts/test_service_scan.py`: 74 tests on recorded greetings, answers and lookups, no network.
- `references/exposure-check.md`: Services and operating system, Published issues for the
  services, What can't be seen from outside, and new severity rows. `SKILL.md`: the two commands,
  and what to say when asked about an OS or kernel CVE.

### Changed

- The ports `scripts/fms_exposure_check.py` tries now live in `references/ports.json` (port, group,
  what uses it, expectation), so other tools can show exactly what's scanned.
- Ports are tried 8 at a time, printed in list order. 82 ports against this Mac took about 9
  seconds; a firewalled server waits up to 4 seconds per filtered port.

## [1.2.2] — 2026-11-08

Two more checks Claris's Security Guide recommends, and a way for a program that has already signed
in to run the settings review. Tested in scans of three servers on 8 November 2026.

### Added

- `scripts/fms_exposure_check.py`: an `HSTS (443)` line from the `Strict-Transport-Security`
  header, and an `Old TLS (443)` line from one TLS 1.0 and one TLS 1.1 handshake. A version the
  scanning Mac can't offer is reported as not tested, so macOS's own Python (LibreSSL) and newer
  OpenSSL both give a true answer.
- `scripts/fms_admin_review.py`: a Perform Script on Server check (script sessions above 0 is to
  review), and `--token-stdin`, which reads an Admin API token from stdin, skips the sign-in and
  sign-out, and runs the same GET-only checks. The checks are now in `review(api)`.

### Fixed

- `scripts/fms_admin_review.py`: a connection error on one endpoint is reported as not read,
  instead of stopping the review.

## [1.2.1] — 2026-11-03

Wording corrections in the changelog and eval notes. No change to the checks.

## [1.2.0] — 2026-11-03

Log patterns for attacks through ODBC/JDBC, and checks for PHP and XML publishing. With thanks to
Wim Decorte for the correct pattern to check the logs for these attacks. Built with
`cadenceux-skill-creator` 2.2.0.

### Added

- `scripts/fms_logcheck.py`:
  - `SIGNED-IN`: an address with failed sign-ins that also signed in, at any date, before or after
    the failures, with the account, time and connection type.
  - `POSSIBLE-COMPROMISE`: that sign-in was over ODBC/JDBC or as a generic account, or a new address
    tried 3+ account names. `SIGNED-IN` alone is often staff mistyping, so it's a question for the
    user, not a verdict.
  - An ODBC/JDBC connections section, because an attacker who gets in first time leaves no failure.
  - `RATE`: 20+ failures from one address in 10 minutes, and `SERVER-ITSELF` for failures from
    127.0.0.1, which are usually scripts and don't count towards `RATE`.
  - PHP and XML requests by status, with any page that was served marked `ANSWERED`, and XML record
    calls counted in `BURST`.
- `scripts/fms_exposure_check.py`: requests FileMaker Server's PHP test page, reports an
  `X-Powered-By` header that names PHP, and says when XML publishing is on.
- `scripts/fms_admin_review.py`: reports PHP on its own line, and a service whose setting couldn't
  be read as not read rather than off.
- `references/server-config.md`: S15, a PHP engine on the machine, checked on the server. FileMaker
  Server no longer installs PHP, but an upgrade may leave an older engine in place.
- Intake and Recovery readiness ask when passwords were last reset: the date only, never the
  password. A restored file brings back its accounts' passwords from the day of that backup.
- Evals: `signed-in-before-failures`, `signed-in-staff-typo`, `php-installed`, `last-password-reset`
  (`evals/results-2026-11-03-v1.2.0.md`).

### Changed

- `references/log-review.md`: the breach test is a success at any time, before or after the
  failures.
- Failed sign-ins show the full count of account names, and more of the names. More generic account
  names are recognised.

### Fixed

- `Event-old.log` wasn't read, so older failed sign-ins were missed.
- Rotated `nginx-access.log-YYYY-MM-DD` files, gzipped or not, weren't read, although the guide says
  to collect them.
- `NEVER-SUCCEEDED` was given to failures older than the Access log, where a sign-in can't be ruled
  out. They're now `BEFORE-ACCESS-LOG`.
- An account name that looks like a typed password is hidden in the output, so it doesn't reach a
  report.
- `references/incident-response.md` and `references/log-review.md` named only port 443 where 2399
  belongs too.
- `references/server-config.md`: the "Versions and security fixes" heading was missing.

### Verified

- The `[fmxdbc]` tag in Event.log, left unverified in 1.1.2, is confirmed, along with
  `JDBC [fmxdbc]` as the connection type in Access.log.

## [1.1.2] — 2026-11-02

ODBC/JDBC (port 2399) as an attack route.

### Added

- `scripts/fms_logcheck.py`: failed sign-ins that came through ODBC/JDBC (`[fmxdbc]` in
  Event.log) get an `XDBC` flag, and the section opens with how many failures came through port
  2399 and from how many addresses.
- `references/log-review.md`: what `XDBC` means and how to weigh it, and that a web rate
  limiter or WAF doesn't see port 2399.
- `references/exposure-check.md`: where a BI or reporting tool needs ODBC/JDBC, allow 2399 only
  from that tool's addresses. 2399 open to any address while in use is High.
- SKILL.md: the attack pattern sprays ODBC/JDBC on 2399 as well as 443, and the defences
  allow-list both.
- Evals: `xdbc-port-2399` added (`evals/results-2026-11-02-v1.1.2.md`).

### Not verified

- The `[fmxdbc]` tag in Event.log: forum posts show the bracket naming the connection type
  (`[fmapp]`, `[fmxml]`), but no real ODBC/JDBC failure line was available to test against.

## [1.1.1] — 2026-10-31

Correction: FileMaker does lock file accounts.

### Fixed

- SKILL.md and `references/server-config.md` said FileMaker Server has no account lockout. The
  Claris FileMaker Security Guide ("Authenticate users") says five failed sign-ins within five
  minutes lock an internal file account for five minutes. The attack pattern now says password
  spraying stays under that limit, which is why a low failure count proves nothing, and the
  server review neither reports the lockout as missing nor counts it as protection.
- `references/log-review.md`: the breach test (a failing address that later signed in
  successfully is possible compromise until the user confirms it), and why a low failure count
  per account isn't reassurance. SKILL.md's attack pattern and log review step name the
  defences against spraying and say a low failure count is never reassurance.
- Evals: `lockout-fact` added. Baseline ❌; Haiku, Sonnet and Opus ✅ after the fixes
  (`evals/results-2026-10-31-v1.1.1.md`).

## [1.1.0] — 2026-10-31

Recovery readiness: plan for when, not if. Built with `cadenceux-skill-creator` 2.2.0.

### Added

- Intake asks for the data owner's recovery expectations: whether there's a written Disaster
  Recovery (DR) plan, how much data they could lose, how long the server could be down, and who
  is called. Unknown answers are recorded as "to agree with the owner" and become a finding;
  they never stop the check. New rule in SKILL.md: plan for when, not if.
- `references/server-config.md`: a Recovery readiness section. S10 (backups) is now judged
  against the owner's expectations: the backup interval (including Progressive Backup) against
  the data-loss limit, a copy beyond the server's network (a NAS the server can write to doesn't
  count), a timed test restore against the downtime limit, and enough history to restore from
  before an attack. No copy beyond the network rates High when the files hold personal data.
- `references/report-format.md`: a Recovery readiness table (the owner's expectation, today,
  the gap, what to do), and a next step to agree the DR plan when there isn't one.
- `references/incident-response.md`: open the DR plan alongside containment (never instead of
  it), choose a restore point from before the attacker's earliest activity, weigh the data gap
  against the owner's data-loss limit, and restore onto a fixed server. Also: disconnect the
  attacker's open sessions (Block New Users leaves them running), check backups the server
  could write to for tampering, check Event.log for server settings a file restore doesn't roll
  back, and run the file audit on restored copies.
- Recovery readiness counts rebuilding the server: backups hold the hosted files, not the
  server's settings, schedules, plug-ins or certificate.
- Evals: `recovery-intake`, `backup-vs-expectation` and `restore-point`. Baseline 0/3; every
  model 4/4 after the fixes (`evals/results-2026-10-31-v1.1.0.md`).

### Changed

- "One automated check" now reads "one skill, a set of automated checks written up in one
  report" in SKILL.md, the README and the report's limits note, to match what the skill runs.

## [1.0.0] — 2026-10-31 (updated 2026-10-31, pre-release)

First release, built with `cadenceux-skill-creator` 2.2.0.

### Added

- Six-step interactive check: intake and authorisation, exposure check, server configuration,
  hosted file security, log review, findings report with re-test.
- `scripts/fms_exposure_check.py`: TCP connect to the ports in Claris's port table, TLS
  certificate check, and unauthenticated GETs of the Admin Console, Admin API, Data API, OData,
  XML, WebDirect and third-party admin paths. Reports file lists shown before sign-in.
- `scripts/fms_admin_review.py`: read-only Admin API review the user runs in their own terminal.
  It asks for the password itself and refuses to run without a terminal.
- `scripts/fms_advisories.py` and `references/security-advisories.md`: FileMaker Server CVEs
  fetched live from NVD on the first request of a session, merged with a bundled list
  (`references/advisories.json`: FileMaker Server, Pro and Cloud CVEs from NVD and 7
  release-note security fixes, checked 2026-10-31), and matched to the server's exact version. The admin review reports how many
  published issues affect the version it reads.
- FileMaker Pro advisories: Pro CVEs are matched to the client builds the log check finds in
  Access.log and reported as "clients to update". FileMaker Cloud CVEs are listed for reference
  only, since Claris patches its own hosting.
- `scripts/fms_file_audit.py`: reads Save a Copy as XML exports of the hosted files, with no
  server connection or ADT: Guest, auto-login (including auto-login to an account that doesn't
  exist), generic and [Full Access] accounts, extended privileges, Encryption at Rest, reference
  protection, passwords typed into script steps, and credentials in Insert from URL.
- `scripts/fms_logcheck.py`: log review for password spraying, generic-account attempts, new
  addresses, admin sign-ins, settings changes, Admin API errors, and bursts of record downloads
  (TopCallStats and Data API/OData calls).
- References for exposure, server configuration, file security, log review and incident
  response.

### Verified

- Ports, log locations, Filter databases, Deny Guest and auto-login, secure-files behaviour,
  Block New Users and version facts checked against Claris's FileMaker Server Help, Security
  Guide, installation guide, KB 000026067, KB 000049228 and release notes on 2026-10-31.
- Admin API endpoints and field names checked against the API reference built into FileMaker
  Server 26.
- All three scripts run against a FileMaker Server 26 in Docker on macOS: the exposure check
  found a file list served without sign-in, the admin review confirmed Filter databases was off,
  and the log check ran over the server's whole log history. The exposure check also ran against
  a production-configured FileMaker Server 26, and the log check against real production logs.
- Fixes from those runs: a first-review mode with no NEW flags, a note when every address is
  private (NAT, proxy or container gateway), GENERIC flags on admin sign-ins, the HTTP-to-HTTPS
  redirect check, development-CA certificates, the default web page, a nested version lookup, and
  a warning that port forwarders such as Docker Desktop's report published ports as open.
- File audit run against the Save a Copy as XML exports of a 34-file production solution and a
  synthetic export covering every finding; it streams large exports (183 MB in about 2 seconds).
- Evals: see `evals/` for the no-skill baseline and the three-model results.

### Fixed before release

- Added the limits of the check: README "Before you use it" section, a rule in SKILL.md, and a
  limits note in the report template (one automated check, offered as is with no guarantee or
  support, not a replacement for a professional security assessment).
- `fms_advisories.py`, `fms_file_audit.py` and `fms_logcheck.py` print their usage for `-h` and
  `--help` instead of treating the flag as a version or a path.
- SKILL.md: the no-code-execution line now covers every script.
- Added `LICENSE`, `.claude-plugin/plugin.json`, `.gitignore` and `.gitattributes` for the
  GitHub repo and the `cadenceux` marketplace.
- The log check counted refused Data API and OData calls (401, 403) as record calls. It now
  counts only answered calls, lists refused ones separately, and bases BURST on answered calls.
  Found by running the installed skill against a FileMaker Server in Docker.
- Server configuration S5 notes that `DenyGuestAndAutoLogin` defaults to `false` (confirmed on
  FileMaker Server 26), and gives the Docker form of the command.
- The findings report is now written for the server's owner by default
  (`references/report-format.md`): a summary table, then "What to fix", "What passed", "Staff
  computers to update", "Not checked" and "Next steps" tables in plain English, with commands and
  evidence kept in a closing section for the FileMaker administrator.
