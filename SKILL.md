---
name: cadenceux-fms-security
description: >-
  Runs an interactive security check of a Claris FileMaker Server the user owns or manages:
  ports, web paths and services exposed to the internet, PHP and XML publishing, server
  misconfigurations, known CVEs (live from NVD) for FileMaker Server and its services, accounts
  and privileges in the hosted files (from Save a Copy as XML exports), every server log for
  password spraying, Guest and auto-login abuse and bulk downloads, and backups against the data
  owner's limits on data loss and downtime. Ends with a ranked findings report, and gives
  containment and restore steps if an attack is under way. Use when asked to security-check,
  audit, harden, pen test or review the logs of a FileMaker Server, to check
  whether a server was hit by an automated FileMaker attack or has known CVEs, or when FMS logs
  (Access.log, Event.log) are shared for review. Not for FileMaker Server installation or
  upgrades, general FileMaker schema, script or privilege-set design, or servers the user isn't
  authorised to test.
license: CC-BY-4.0
compatibility: >-
  Designed for Claude Code, where it runs the bundled Python scripts (standard library only).
  In Claude.ai and Claude Desktop it gives the user the commands to run and reads the output.
  The file audit needs FileMaker Pro to make Save a Copy as XML exports. Claris ADT is optional.
metadata:
  author: Darrin Southern, CadenceUX
  version: "1.3.0"
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
- **One skill, not a professional audit.** Say so once in intake and again in the report: this
  is one skill, a set of automated checks written up in one report, offered as is with no
  guarantee or support, and it doesn't replace a security assessment by professionals.
- **Plan for when, not if.** Recovery expectations belong to the data owner, not the developer
  or Claude. Ask for them, never assume them, and judge the backups against them.

## Keep the context small

A full scan used to fill the conversation with every check's raw output, then re-read it on every
turn. The scripts now do the reading:

- Run `scripts/fms_scan.py` and read **only what it prints** (also saved as `summary.txt`, about
  5 KB). Never open `findings.json`, `logcheck.txt` or `exposure.txt` whole: `grep` them for the one
  address or code a question needs (each finding is one line of `findings.json`).
- Don't look addresses up (whois, reverse DNS) or search the raw logs unless the user asks: confirm
  who an address is with the user, as the rules say.
- Read a reference **only for the step at hand**, and only the section the question needs.
- Finish `report-draft.md` with edits; don't rewrite the report from scratch.
- Never paste a check's output back into the conversation.

Sonnet is enough for a scan: the scripts make the judgements, and the model confirms and writes.

## Workflow

Copy this checklist into the response and tick it off. The user can ask for any one step on
its own; do intake first regardless.

```
FMS security check:
- [ ] 1. Intake: scope, authorisation, intended exposure, recovery expectations
- [ ] 2. Run the scan: exposure, services, published issues and logs, in one command
- [ ] 3. Server configuration (the user runs the Admin API review)
- [ ] 4. Hosted file security (Save a Copy as XML exports)
- [ ] 5. Confirm addresses and judge what the scan found
- [ ] 6. Finish the report and re-test
```

### 1. Intake

Ask in one message (with the ask-user tool where the surface has one):

1. Server hostname, and confirmation the user owns or manages it, or has permission to test it.
2. Who hosts it (own hardware, cloud, a hosting provider) and who else holds admin access:
   hosting providers, management tools and anything holding Admin API keys.
3. FileMaker Server version and operating system, if known.
4. Which services are meant to be used: FileMaker Pro and Go, WebDirect, Data API, OData,
   ODBC/JDBC, XML, PHP, Admin Console, Admin API. This is the **intended exposure**; every finding
   is judged against it.
5. Where the logs are: the whole Logs folder as a zip, and the web-server access log.
6. Which hosted files exist, including deployment and utility files, and whether the user can
   open each with a [Full Access] account in FileMaker Pro (needed for the file audit).
7. Whether code execution is available here (Claude Code), or the user will run commands.
8. **Recovery expectations, from the data owner.** Who owns the data; whether there's a written
   Disaster Recovery (DR) plan; how much data they could lose; how long the server could be down
   before it hurts the business; who is called when it happens; and when passwords were last
   reset (the date only, never the password). If they're unknown, record "to agree with the
   owner" and carry on: the gap becomes a finding, never a reason to stop.

### 2. Run the scan

From **outside** the server's network (inside it, or on a VPN, the exposure check shows what the
firewall allows internally; say so if that's the only option):

```bash
python3 scripts/fms_scan.py <hostname> --logs <logs.zip or folder> --version <FMS version> --intended "<services from intake>"
```

Run it from the user's working folder (where the report goes), giving the script's full path; don't
`cd` into the skill. Leave out `--logs` or `--version` when there are none; the version is then read from outside if
the server shows it. It runs the exposure check (82 ports, the certificate, the FileMaker web
paths, and what each open port says, with no sign-in), published issues for the services found
and for FileMaker Server, and the whole log review. It saves everything in
`fms-scan-<hostname>-<date>/`, writes `findings.json` and `report-draft.md`, and prints the summary.
The single checks are in [references/scripts.md](references/scripts.md), for re-running one.

Asked about an operating system or kernel CVE? Nothing a server shows before sign-in reveals its
patch level, so no outside check (or attacker) can confirm or rule it out. Say so, check the
vendor's page for the CVE, and point to the server's own updates.

### 3. Server configuration

Read [references/server-config.md](references/server-config.md). Ask the user to run the Admin
API review **in their own terminal** and paste the FAIL and REVIEW lines:

```bash
python3 scripts/fms_admin_review.py <hostname>
```

It asks for the Admin Console password itself and refuses to run without a terminal, so never
run it for them and never take the password. Then cover what it can't see (Deny Guest and
auto-login, backups, a PHP engine on the machine (S15), who else holds admin access) one area at
a time, a screenshot or a yes/no per item. Judge backups (S10) against the recovery expectations
from intake.

### 4. Hosted file security

Read [references/file-security.md](references/file-security.md). Check every hosted file. The
user saves each with **Tools > Save a Copy as XML** into one folder, then run:

```bash
python3 scripts/fms_file_audit.py <folder of .xml exports>
```

Claris ADT is **optional**: use it only if it's already installed, to add the blank-password
check SaXML can't make. Never ask the user to install it for this.

### 5. Confirm addresses and judge

Go through the summary's "Addresses to confirm" with the user, worst first. For what a flag means,
read the matching part of [references/log-review.md](references/log-review.md); for a port, web
path or service, [references/exposure-check.md](references/exposure-check.md); for a published
issue, [references/security-advisories.md](references/security-advisories.md).

A clean result needs the logs to cover the period in question; a gap is a limit on the verdict,
never a pass. A low failure count or the account lockout is never reassurance (spraying stays under
the lockout): name the defences, strong unique passwords, allow-listing 443 and 2399 or a VPN, and
a rate limiter or WAF. `POSSIBLE-COMPROMISE` means stop and confirm who it is; `SIGNED-IN` alone is
often staff mistyping, so ask rather than assume.

**If anything points to an attack in progress or a compromise**, stop the review and follow
[references/incident-response.md](references/incident-response.md) first.

### 6. Finish the report and re-test

Read [references/report-format.md](references/report-format.md), then edit `report-draft.md` in
place (small edits, not a rewrite):
fill every TODO from intake and the user's answers, rewrite each row in plain English for the
server's owner, add the server settings and file audit findings, set owners, and save it as
`FMS security check - <server> - <YYYY-MM-DD>.md` (or put it in the reply where no files can be
written). After the user fixes items, re-run `fms_scan.py` and update the Status column. Suggest a
log check schedule from [references/log-review.md](references/log-review.md).

## Without code execution

Give the user the `fms_scan.py` command, then ask for `summary.txt` and `report-draft.md` from the
scan folder: about 15 KB in all, instead of every check's output.

## Skill update self-check

Once per session, on the first request this skill handles: fetch
`https://github.com/CadenceUX/cadenceux-fms-security-skill/raw/main/VERSION` and compare it with
this skill's `metadata.version`. If newer, start the answer with:

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
