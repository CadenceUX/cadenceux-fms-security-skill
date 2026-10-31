# FileMaker security advisories

Published security issues in FileMaker Server and FileMaker Pro, which releases fix them, and
how to match them to a version. Checked **2026-10-31**. The data lives in `advisories.json` (next to
this file) and is refreshed live from NVD by `scripts/fms_advisories.py`.

## Contents
- First call: refresh the list
- Matching a server's version
- Latest releases
- CVEs
- Security fixes in the release notes
- FileMaker Pro clients
- FileMaker Cloud
- Rules for reporting

## First call: refresh the list

Once per session, on the first request, alongside the skill update check:

```bash
python3 scripts/fms_advisories.py
```

It makes one request to NVD's public CVE API, merges the result with the bundled list, and
says which source it used. If NVD can't be reached it uses the bundled list and says how old
it is. Without code execution, fetch
`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=FileMaker` and read
the newest entries, or use the tables below and state their date.

Also check Claris's release notes
(https://help.claris.com/en/server-release-notes/content/) for a release newer than those
below; the script flags it when NVD names a fixed version newer than the bundled latest.

## Matching a server's version

As soon as intake gives the version (or the admin review reports it):

```bash
python3 scripts/fms_advisories.py <version>
```

It lists every published issue that version is still exposed to, highest CVSS first, with
the fixed release and the Claris source. Put each FileMaker Server issue in the report: CVSS 7 or
more is High (9 or more, and reachable from the internet, Critical); the rest Medium. FileMaker
Pro issues follow their own rule below, whatever their CVSS. Release-note fixes have no CVSS:
remote code execution or an authorisation bypass is High, anything else Medium.

## Latest releases

| Line | Latest at 2026-10-31 | Notes |
|---|---|---|
| 26 | 26.0.3 | Current line |
| 22 | 22.0.7 | Several 2026 CVEs list a fix only in 26.0.x |
| 21 | 21.1.8 | Oldest line still receiving fixes |
| 20 and older | — | Unsupported: no security fixes |

## CVEs

From NVD; the source is Claris's own article where NVD links one. Fixed versions are NVD's
affected ranges.

| CVE | CVSS | Issue | Fixed in |
|---|---|---|---|
| CVE-2026-86930 | 9.1 | Linux: out-of-bounds read from an image uploaded to a container field | 26.0.3 (KB 000049218) |
| CVE-2026-86934 | 9.1 | Web Publishing Engine: an extended-privilege header bypasses **disabled** XML publishing | 26.0.3 (KB 000049217) |
| CVE-2026-86926 | 7.8 | Heap overflow from a crafted .fmp12 file | 26.0.3 (KB 000049219) |
| CVE-2026-43752 | 4.9 | Authenticated administrator code execution through the Open Source LLM setup upload | 26.0.1 |
| CVE-2025-46320 | 6.1 | XSS in a WebDirect custom homepage | 22.0.4, 21.1.7 (KB 000049123) |
| CVE-2025-46295 | 9.8 | Apache Commons Text remote code execution | 22.0.4 (KB 000049059) |
| CVE-2025-46296 | 5.4 | Admin Console: minimal admin roles reach administrative functions | 22.0.4 (KB 000049056) |
| CVE-2025-46294 | 5.3 | Windows: IIS short-filename enumeration (installer option) | 22.0.4 (KB 000048450) |
| CVE-2024-27790 | 7.5 | Unauthorised access to records | 20.3.2 |
| CVE-2024-27794 | 6.1 | Reflected XSS | 20.3.2 |
| CVE-2023-42955 | 4.9 | Admin role passwords exposed in the Admin Console | 20.3.1 |
| CVE-2023-42954 | 4.9 | Privilege escalation exposing information to front-end users | 20.3.1 |
| CVE-2021-44147 | 5.5 | XML external entity issue (Pro and Server, including WebDirect) | 19.4.1 |

## Security fixes in the release notes

Claris lists these in its release notes without their own CVE. They're matched only on the
lines Claris names.

| Fix | Fixed in |
|---|---|
| Path traversal to remote code execution through system-level script schedules; Admin Console tokens moved out of local storage | 22.0.6, 21.1.8 |
| Tomcat CVE-2025-31650, -55752, -55754, -61795; Admin Console path traversal | 22.0.5, 21.1.7 |
| Two further authenticated-administrator code-execution fixes; SameSite cookies | 26.0.1 |
| Linux: ImageMagick CVE-2025-55004 | 26.0.3 |
| Denial-of-service hardening; clients older than 21.0.1 blocked | 22.0.1 |
| Admin roles could exceed their privileges | 21.1.5 |
| Admin Console Restrict Access bypass with a forged X-Forwarded-For header | 21.0.1 |

## FileMaker Pro clients

Every client that connects is in Access.log with its build (for example `Pro 26.0.3 [fmapp]`).
The log check lists each FileMaker Pro and Go build that connected and flags Pro builds with a
published issue; `python3 scripts/fms_advisories.py <version> --pro` gives the detail.

| CVE | CVSS | Issue | Fixed in |
|---|---|---|---|
| CVE-2026-86938 | 7.3 | Windows: DLL hijacking in the FileMaker Pro **installer** lets a local user run code with administrator rights | 26.0.3 (KB 000049220) |
| CVE-2023-42920 | 7.8 | macOS: dylib hijacking in the FileMaker Pro / Claris Pro app | 20.2 |
| CVE-2021-44147 | 5.5 | XML external entity issue (FileMaker Pro and Server) | 19.4.1 |

These run on staff computers, not the server: report them as "clients to update", Medium
whatever their CVSS (they need local access to the machine), in their own section of the report.
High only when the client is a shared machine or a server. The log shows the build but not the platform, so ask which
machines are Windows or macOS before applying a platform-only CVE. A client running FileMaker
Pro on a server (a machine name like a server's) carries both the client and the server risk.

## FileMaker Cloud

CVE-2026-43680 and CVE-2026-43685 (CVSS 7.2, remote code execution by an Admin Console user,
fixed in 2.22.0.5). Claris patches FileMaker Cloud itself: mention them only if the user runs
Cloud, and never match them to a FileMaker Server.

## Rules for reporting

- **Confirmed** means published by NVD or Claris. Mark anything seen only on third-party sites
  "unconfirmed", and never report it as a finding on its own.
- When NVD lists a fix only on a newer line (for example "before 26.0.3" for a 22.x server),
  say exactly that: no fix is listed for the server's line, so upgrade, or confirm in the
  Claris article whether that line is affected.
- Platform-specific issues (Linux, Windows IIS) apply only to servers on that platform.
- Always give the date of the data used. When adding a release, update `latest` in
  `advisories.json` and the tables here.
