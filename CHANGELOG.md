# Changelog

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
