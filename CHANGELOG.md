# Changelog

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
