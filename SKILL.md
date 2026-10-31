---
name: cadenceux-fms-security
description: >-
  Runs an interactive security check of a Claris FileMaker Server the user owns or manages:
  ports and web paths exposed to the internet, server misconfigurations, known CVEs for its
  version (live from NVD), accounts and privileges in the hosted files (from Save a Copy as XML
  exports), and a review of every server log for password spraying, Guest and auto-login abuse,
  and bulk record downloads through the Data API or OData. Ends with a ranked findings report,
  and gives containment steps if an attack is under way. Use when asked to security-check,
  audit, harden, pen test or review the logs of a FileMaker Server or hosted FileMaker files,
  to check whether a server was hit by an automated FileMaker attack or has known CVEs, or when
  FMS logs (Access.log, Event.log, TopCallStats.log, an nginx access log) are shared for review.
  Not for FileMaker Server installation or upgrades, general FileMaker schema, script or
  privilege-set design, or servers the user isn't authorised to test.
license: CC-BY-4.0
compatibility: >-
  Designed for Claude Code, where it runs the bundled Python scripts (standard library only).
  In Claude.ai and Claude Desktop it gives the user the commands to run and reads the output.
  The file audit needs FileMaker Pro to make Save a Copy as XML exports. Claris ADT is optional.
metadata:
  author: Darrin Southern, CadenceUX
  version: "1.0.0"
---

# FileMaker Server security check

An interactive check of one FileMaker Server: what the internet can reach, how the server is
set up, how the hosted files are protected, and what the logs show. Built from security reviews
of production FileMaker Servers during a wave of automated attacks, and from Claris's own
guidance.

## Rules for every check

- **Authorised servers only.** Before probing anything, confirm the user owns or manages the
  server or has written permission to test it. If not, stop and explain why.
- **Non-destructive.** Connection checks and unauthenticated requests only. Never try
  passwords or account names, run exploits, or run aggressive scans (they can trip the host's
  intrusion detection and lock the user out).
- **No secrets in chat.** Never ask for or accept passwords, API keys or tokens. The user signs
  in to the Admin Console and FileMaker Pro themselves and reports what they see.
- **Ask, don't assume, who an address is.** Confirm machines, addresses and accounts with the
  user before calling them staff or attackers.
- **The report is sensitive.** It holds addresses, account names and weaknesses. Save it
  locally and tell the user not to publish it.
- **One check, not a professional audit.** Say so once in intake and again in the report: this
  is one automated check, offered as is with no guarantee or support, and it doesn't replace a
  security assessment by professionals.

## Workflow

Copy this checklist into the response and tick it off. The user can ask for any one step on
its own; do intake first regardless.

```
FMS security check:
- [ ] 1. Intake: scope, authorisation, intended exposure
- [ ] 2. Exposure check from outside the network
- [ ] 3. Server configuration
- [ ] 4. Hosted file security
- [ ] 5. Log review
- [ ] 6. Findings report and re-test
```

### 1. Intake

**First, refresh the security advisories** (once per session, with the skill update check):
run `python3 scripts/fms_advisories.py`, which fetches FileMaker CVEs live from NVD and
falls back to the bundled list. Read
[references/security-advisories.md](references/security-advisories.md) for the rules.

Ask in one message (with the ask-user tool where the surface has one):

1. Server hostname, and confirmation the user owns or manages it, or has permission to test it.
2. Who hosts it (own hardware, cloud, a hosting provider) and who else holds admin access:
   hosting providers, management tools and anything holding Admin API keys.
3. FileMaker Server version and operating system. As soon as you have the version, run
   `python3 scripts/fms_advisories.py <version>` and carry every published issue it lists into
   the report.
4. Which services are meant to be used: FileMaker Pro/Go remotely, WebDirect, Data API, OData,
   ODBC/JDBC, XML. This is the **intended exposure**; every finding is judged against it.
5. Which hosted files exist, including deployment and utility files, and whether the user can
   open each with a [Full Access] account in FileMaker Pro (needed for the file audit).
6. Whether code execution is available here (Claude Code), or the user will run commands.

### 2. Exposure check

Read [references/exposure-check.md](references/exposure-check.md), then run from **outside** the
server's network:

```bash
python3 scripts/fms_exposure_check.py <hostname>
```

It covers the FileMaker ports, the certificate, and every web path that matters: Admin Console,
Admin API, Data API, OData, XML, WebDirect, and the sign-in pages of third-party admin and
deployment tools installed on the server. Ask in intake which such tools are installed and add
their paths. Running it from inside the network or a VPN shows what the firewall allows
internally, not what the internet sees; say so if that's the only option. Judge every open port
and reachable path against the intended exposure.

### 3. Server configuration

Read [references/server-config.md](references/server-config.md). Ask the user to run the Admin
API review **in their own terminal** and paste the output:

```bash
python3 scripts/fms_admin_review.py <hostname>
```

It asks for the Admin Console password itself and refuses to run without a terminal, so never
run it for them and never take the password. Then cover what it can't see (Deny Guest and
auto-login, backups, the operating system, who else holds admin access) with the user, one
area at a time, asking for a screenshot or a yes/no per item.

### 4. Hosted file security

Read [references/file-security.md](references/file-security.md). Check every hosted file, not
only the main solution. The default needs nothing beyond FileMaker Pro: the user saves each file
with **Tools > Save a Copy as XML** into one folder, then run:

```bash
python3 scripts/fms_file_audit.py <folder of .xml exports>
```

Claris ADT is **optional** and uncommon: use it only if it's already installed, to add the
blank-password check SaXML can't make. Never ask the user to install it for this.

### 5. Log review

Read [references/log-review.md](references/log-review.md). Ask for the whole Logs folder as a zip
and the web-server access log, then run:

```bash
python3 scripts/fms_logcheck.py <logs.zip or folder> ["YYYY-MM-DD HH:MM"]
```

Go through each flagged address with the user. A clean result needs the logs to cover the
period in question; a gap is a limit on the verdict, never a pass.

### 6. Findings report and re-test

Read [references/report-format.md](references/report-format.md) and write the report in that
format: written for the server's owner, in tables and plain English. It has a summary table,
"What to fix" (priority, what we found, why it matters, what to do, owner, status), "What
passed", "Staff computers to update", "Not checked", "Next steps", and a closing section for the
FileMaker administrator that holds the commands and evidence. Save it as a Markdown file in the
user's working folder (or put it in the reply where no files can be written).

Order findings Critical, High, Medium, Check, Low (definitions in each reference). After the user
fixes items, re-run the exposure check and the affected checks, and update the Status column.
Suggest a log check schedule from [references/log-review.md](references/log-review.md).

**If anything points to an attack in progress or a compromise**, stop the review and follow
[references/incident-response.md](references/incident-response.md) first.

## What the automated attacks do

The pattern Claris described (support.claris.com, KB 000049228, "Protecting FileMaker Server
from automated attacks") and that this skill's checks look for:

1. Ask the server for its hosted file list through the web APIs (it needs no sign-in unless
   Filter databases and Deny Guest and auto-login are both on).
2. Open each file through Guest, auto-login, or a default Admin account with no password.
3. Spray common passwords at generic account names, rotating addresses. FileMaker Server has
   no account lockout, so nothing on the server slows this down.
4. Once in, pull records through the Data API, 200 at a time, across every layout available.

No FileMaker Server flaw is involved: every step works through configuration. Steps 2 and 4
leave no failed sign-in, which is why the log review checks downloads as well as failures.

## Scripts

All five are run, not read, and need only Python 3 (built into macOS and most Linux; on
Windows install it from python.org).

| Script | What it does |
|---|---|
| `scripts/fms_advisories.py` | Fetches FileMaker CVEs live from NVD (one request), merges Claris release-note fixes from `references/advisories.json`, and lists every published issue a given FileMaker Server version (or FileMaker Pro version, with `--pro`) is exposed to. Falls back to the bundled list offline and says how old it is |
| `scripts/fms_file_audit.py` | Reads Save a Copy as XML exports, no server connection: Guest, auto-login, generic and [Full Access] accounts, extended privileges, Encryption at Rest, reference protection, passwords typed into scripts, credentials in Insert from URL. Never prints hashes or script text |
| `scripts/fms_admin_review.py` | Run **by the user** in their own terminal: signs in to the Admin API, reads version, certificate, secure-files, Admin Console restriction, Filter databases, services, per-file API privileges and encryption, connected Guest sessions, admin roles, schedules and plug-ins (GET only), signs out |
| `scripts/fms_exposure_check.py` | TCP connect to FileMaker and admin ports, HTTP-to-HTTPS redirect and TLS certificate checks, unauthenticated GET of the FileMaker web paths. Reports open ports, file lists shown before sign-in, the default web page, and services answering |
| `scripts/fms_logcheck.py` | Reads a Logs folder or zip: new addresses, FileMaker Pro/Go client builds with published issues, flagged failed sign-ins, admin sign-ins, settings and file events, Admin API errors, record download bursts, web-server requests |

Without code execution, give the user the command for each script and ask them to paste the
output.

## Skill update self-check

Once per session, on the first request this skill handles: fetch
`https://github.com/CadenceUX/cadenceux-fms-security-skill/raw/main/VERSION` and compare it with
this skill's version (1.0.0). If newer, start the answer with:

> ⚠️ **Skill update available:** this skill is v[installed]; v[latest] is at
> https://github.com/CadenceUX/cadenceux-fms-security-skill/releases

Skip silently if the fetch fails. If the skill was installed as a plugin, suggest
`claude plugin update` (or the Plugins page on claude.ai) instead. If `fmp-dev-orchestrator` is
installed, skip this check: its stack check covers every CadenceUX skill.

## Relationship to other skills

- **cadenceux-fms-docker-setup** installs and upgrades FileMaker Server; this skill checks a
  running server. Its certificate and connector steps are where to fix findings on Docker
  installs.
- **claris-filemaker-pro** answers FileMaker function, script step and Data API questions; this
  skill doesn't repeat them.
- **filemaker-agentic-development** (Claris ADT): optional, and not needed for any step. When
  it's already installed, its `fm-cli` skill reads accounts (including whether each has a
  password), privilege sets and extended privileges straight from hosted files (step 4).

## Licence

This skill is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Built and maintained by [Darrin Southern](https://www.linkedin.com/in/darrin-southern/) from [CadenceUX](https://cadenceux.com.au).
