# Server configuration

Facts from Claris's FileMaker Server Help, the Security Guide, KB 000049228 and the Admin
API reference built into FileMaker Server (`https://<host>/fmi/admin/apidoc/`), checked
2026-10-31 against FileMaker Server 26.

## Contents
- How to read the settings
- Checks
- Recovery readiness
- Versions and security fixes
- Who else holds admin access
- Severity

## How to read the settings

Use the first route that's available. Never ask for the Admin Console password.

1. **Admin API review (default).** The user runs `scripts/fms_admin_review.py <host>` in their
   own terminal. It asks for the password itself, reads settings with GET requests only, signs
   out, and prints PASS / REVIEW / FAIL lines to paste back. Claude can't run it: it refuses to
   run without a terminal, so no password passes through Claude.
2. **Command line on the server**, for settings the Admin API doesn't show. The user runs:
   ```bash
   fmsadmin get serverprefs DenyGuestAndAutoLogin
   fmsadmin get serverconfig
   fmsadmin list files -s
   ```
   `fmsadmin` asks for the admin account itself. Run `fmsadmin help` for anything else; Claris
   publishes no full command reference.
3. **Guided Admin Console.** One area at a time, ask for a screenshot or a yes/no per check.

## Checks

| # | Check | Where | Pass |
|---|---|---|---|
| S1 | Version | Admin Console dashboard; `serverVersion` | The latest release of a supported line (see below) |
| S2 | Admin Console access | Administration > Restrict Access > Enable Access Restriction | On, with only management addresses. Before 21.0.1 this could be bypassed with a forged header, so upgrade too |
| S3 | Admin Console accounts | Administration > External Authentication; Administrator Roles (21.0.1+) | Named accounts through an identity provider or admin roles; the built-in account kept for emergencies, with a strong password not shared with other servers |
| S4 | Filter databases in client applications | Configuration > FileMaker Clients | On (default from 2024). It hides the file list in FileMaker Pro, Go, WebDirect and the Data API |
| S5 | Deny Guest and auto-login | `fmsadmin get serverprefs DenyGuestAndAutoLogin` (in Docker: `docker exec -it <container> fmsadmin …`) | `true`. **The default is `false`**, so expect to set it: `fmsadmin set serverprefs DenyGuestAndAutoLogin=true`. With S4 on, the Data API file list then needs credentials |
| S6 | Secure files only | `requireSecureDB` in the admin review; `SecureFilesOnly` in `fmsadmin get serverconfig` | On (the default). Files where Guest has [Full Access], a [Full Access] account has no password, or auto-login uses a [Full Access] account can't be hosted |
| S7 | Unused services | Connectors: Data API, OData, XML, PHP, ODBC/JDBC, WebDirect | Every service not in the intended exposure is off |
| S8 | SSL certificate | Configuration > SSL Certificate | A trusted certificate, not the Claris test certificate, not near expiry |
| S9 | Logging | Logs > Log Settings | Top call statistics on (needed to see record downloads); logs copied off the server daily |
| S10 | Backups | Backups; Progressive Backup; schedules; the recovery expectations from intake | The backup interval is no longer than the data the owner can lose; at least one copy beyond the server's network; a restore tested and timed within the downtime the owner can bear (see Recovery readiness) |
| S11 | Schedules and plug-ins | Schedules; Plug-ins | Every enabled schedule and plug-in is expected. System-level script schedules run with operating-system rights |
| S12 | Perform Script on Server | Configuration > Script Engine | Limited to what's needed (`fmsadmin set serverconfig scriptsessions=0` turns it off) |
| S13 | Encryption at Rest | Databases (the admin review lists unencrypted files) | Files with personal or sensitive data encrypted |
| S14 | Operating system | Server host | Remote Desktop and screen sharing off or allow-listed; OS updates current; a WAF or rate limiter in front of 443 where the APIs are public |

FileMaker **locks an internal file account for five minutes** after five failed sign-ins within
five minutes (Security Guide, "Authenticate users"). Externally authenticated and OAuth accounts
follow their identity provider's rules. Password spraying stays under that limit, so a low
failure count proves nothing: allow-listing, a rate limiter or WAF, and strong unique passwords
remain the defences. Don't report the lockout as missing, and don't count it as protection.

## Recovery readiness

Judge S10 against the recovery expectations the data owner gave in intake, never against a
generic standard. Record each in the report's Recovery readiness table, and every gap as a
finding with a priority and an owner (who fixes it: the developer, the hosting provider, IT).

- **Data loss.** Compare the owner's limit with the gap between backups: scheduled backups,
  plus Progressive Backup where it's on. Nightly backups against a one-hour limit is a finding.
- **A copy beyond reach.** Claris advises keeping at least one copy on a separate system or
  location that isn't reachable from the server's network, and testing a restore (KB
  000049228). A NAS or file share the server can write to is on the network: an attacker or
  ransomware that reaches the server can reach it too.
- **Down time.** A restore that has never been tested leaves the owner's downtime limit
  unverified. Ask how long the last test restore took, from copying the files back to users
  signing in, and compare it with the limit. If the server itself could be lost, count the
  rebuild too: backups hold the hosted files, not the server's settings, schedules, plug-ins or
  certificate, so keep a record of those to rebuild from.
- **Reach back before an attack.** Keep enough backup history to restore from before the
  earliest suspicious activity: reconnaissance can come days before the attempt (KB 000049228).
- **The plan itself.** A written DR plan, agreed with the data owner, that names who is called
  and in what order. Expectations nobody has agreed go in the report as "to agree with the
  owner", rated Check.


Match the server's version against `security-advisories.md` with `scripts/fms_advisories.py
<version>`, which also checks NVD live. The admin review reports how many published issues
affect the version it reads. Latest releases per line, checked 2026-10-31: **26.0.3**,
**22.0.7**, **21.1.8**; line 20 and older are unsupported. When Claris ships a release, update
`latest` in `advisories.json`, the tables in `security-advisories.md`, and `LATEST` in
`scripts/fms_admin_review.py`.

## Who else holds admin access

Ask, and list each in the report:

- Hosting providers that sign in to the Admin Console or Admin API for monitoring.
- Management and deployment tools that store Admin API keys or admin passwords (and where
  those are stored: on the tool vendor's servers counts).
- Integrations with their own FileMaker accounts.

Each should have its own login or key, so it can be revoked alone. A tool still signing in
with an old password shows up in the log review as daily admin sign-in failures.

## Severity

| Severity | Examples |
|---|---|
| Critical | Version with a published remote-code-execution fix outstanding; S6 off; Admin Console open to any address on a version before 21.0.1 |
| High | S2 off; shared or default admin credentials; S4 or S5 off; default certificate |
| High | No copy beyond the server's network when the files hold personal data |
| Medium | Unused services on; no top call statistics; no off-network backup; backup interval longer than the owner's data-loss limit; restore never tested; no DR plan agreed with the owner; unexpected schedules or plug-ins |
| Low | No admin roles on a server with one administrator |
