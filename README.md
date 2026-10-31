# cadenceux-fms-security

A Claude skill that runs an interactive security check of a Claris FileMaker Server you own or
manage. It checks what the internet can reach, how the server is set up, how the hosted files
are protected, and what the server logs show, then writes a ranked findings report.

It was built from security reviews of production FileMaker Servers during a wave of automated
attacks on FileMaker Server, and from Claris's published guidance.

Built and maintained by [Darrin Southern](https://www.linkedin.com/in/darrin-southern/) from [CadenceUX](https://cadenceux.com.au).

## Before you use it

This is **one skill**, not a security audit. It runs a set of automated checks (the host from
outside your network, the server's settings, the hosted files and the server logs) and writes one
report.
It does **not** replace a security assessment by professionals, and a clean report is not a
promise that the server is safe.

The skill is offered **as is**, with no guarantee of any kind and no support. You run it at your
own risk, against servers you're authorised to test.

## What it does

When this skill is active, Claude will:

- Confirm you're authorised to test the server, and record which services are meant to be used
- Ask for the data owner's recovery expectations: whether there's a Disaster Recovery (DR) plan,
  how much data they could lose, and how long the server could be down
- Check from outside your network which ports answer, whether the TLS certificate is trusted,
  and which FileMaker web paths respond without signing in, including whether the hosted file
  list is shown to anyone (`scripts/fms_exposure_check.py`)
- Walk you through the Admin Console settings that matter, one area at a time, and judge the
  backups against those expectations: how often they run, a copy beyond the server's network,
  and a timed test restore
- Check your FileMaker Server version, and the FileMaker Pro builds that connect to it, against
  published CVEs and Claris's release-note security fixes, fetched live from NVD at the start of each session, with a dated built-in
  list as the fallback (`scripts/fms_advisories.py`)
- Audit every hosted file from its Save a Copy as XML export: Guest, auto-login, default and
  generic accounts, extended privileges, Encryption at Rest, reference protection, and passwords
  typed into scripts (`scripts/fms_file_audit.py`). No extra tools needed; Claris ADT, if you
  already have it, adds a blank-password check
- Review the server logs for password spraying, attempts on generic accounts, admin sign-ins
  from new addresses, unexpected changes, and bulk record downloads through the Data API or
  OData, which leave no failed sign-in (`scripts/fms_logcheck.py`)
- Write a plain-English findings report in tables, written for the server's owner: what to fix
  (ranked Critical to Low, with who owns each fix), what passed, and what wasn't checked; then
  re-test after you fix things
- Switch to containment steps if the evidence points to an attack in progress, and help choose
  a backup from before the attack to restore

## What it won't do

- Test a server you aren't authorised to test
- Try passwords, guess accounts, run exploits or aggressive scans
- Ask for your passwords or API keys

## Requirements

- Python 3 for the scripts (standard library only).
- FileMaker Pro and a [Full Access] account, to export each hosted file with
  Tools > Save a Copy as XML for the file audit.
- Nothing else. Claris ADT is **not required**; if you already have it, Claude uses it to add a
  blank-password check.

In Claude Code, Claude runs the scripts. In Claude.ai or Claude Desktop, Claude gives you the
commands and reads the output you paste back. The admin review always runs in your own terminal,
because it asks for the Admin Console password. Run the exposure check from outside the server's
network.

## Install

**Claude Code** (from the `cadenceux` plugin marketplace):

```bash
claude plugin marketplace add https://github.com/CadenceUX/cadenceux-skills.git
claude plugin install cadenceux-fms-security@cadenceux
```

**claude.ai and Cowork:** Customize → Plugins → Add marketplace from GitHub →
`CadenceUX/cadenceux-skills`, then install **cadenceux-fms-security**.

**Claude desktop app (macOS):** download [`cadenceux-fms-security.skill`](https://github.com/CadenceUX/cadenceux-fms-security-skill/releases/latest/download/cadenceux-fms-security.skill) and
double-click it.

**Claude.ai in a browser, as a single skill:** Customize → Skills → upload
[`cadenceux-fms-security.zip`](https://github.com/CadenceUX/cadenceux-fms-security-skill/releases/latest/download/cadenceux-fms-security.zip).

> Both files are attached to the latest [release](https://github.com/CadenceUX/cadenceux-fms-security-skill/releases).
> Don't use GitHub's green **Code → Download ZIP** button or a release's **Source code (zip)**:
> those are snapshots of the repository, not a packaged skill, and Claude won't install them
> as one.

## A note on the report

The findings report lists addresses, account names and weaknesses. Keep it private.

## Licence

[CC BY 4.0](LICENSE). Use it, fork it, adapt it. Attribute it. As the licence says, it comes
with no warranties.

Built and maintained by [Darrin Southern](https://www.linkedin.com/in/darrin-southern/) from [CadenceUX](https://cadenceux.com.au).
