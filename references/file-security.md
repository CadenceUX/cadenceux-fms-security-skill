# File security review

Review **every hosted file**, not only the main solution: deployment tools, utility files,
sample files and old copies are hosted on the same server and accept the same attacks. Files
that nobody needs should be closed and removed from the server.

## Contents
- How to read the settings
- Checks per file
- External authentication
- Replacing Guest and auto-login
- After changes, test
- Passwords across servers
- Severity

## How to read the settings

**No extra tools are needed.** The default route uses only FileMaker Pro and Python. Claris ADK
is optional: most FileMaker developers don't have it, so never ask anyone to install it for this
check. Use it only if it's already in the session.

1. **SaXML audit (default).** For each hosted file, the user opens it in FileMaker Pro with a
   [Full Access] account and chooses **Tools > Save a Copy as XML**, saving all exports into one
   folder. (Many files: a script using the Save a Copy as XML step, which also runs on FileMaker
   Server, can export them on a schedule.) Then run:
   ```bash
   python3 scripts/fms_file_audit.py <folder of .xml exports>
   ```
   It reads, per file: Guest, auto-login, generic and [Full Access] accounts, extended
   privileges by privilege set, re-authentication, export rights, the fmplugin protection, the
   minimum client version, Encryption at Rest, reference protection, passwords typed into
   script steps, and credentials in Insert from URL. The exports hold password hashes and every
   script, so scan them locally, never upload them, and delete them when the review is done.
2. **ADK, only if already installed.** It adds the one thing SaXML can't show: whether an
   account has a password at all (blank passwords). Use the `fm-cli` skill and `filemaker help
   account` for the exact read command; it reaches hosted files over `fmnet://` and signs in
   with ADK's own stored credentials, never a password typed into the chat.
3. **Guided**, when neither is possible: ask the user to open each file with a [Full Access]
   account and report or screenshot **Manage > Security** (accounts, privilege sets, extended
   privileges) and **File > File Options** (the Open tab). One file at a time.

| Check | SaXML audit | ADK (optional) | Guided |
|---|---|---|---|
| F1 Guest, F2 auto-login, F3 generic names, F5 [Full Access] count | ✅ | ✅ | ✅ |
| F4 blank passwords | ❌ hash only | ✅ `hasPassword` | ✅ user checks |
| F6–F7 extended privileges | ✅ | ✅ | ✅ |
| F9 Encryption at Rest | ✅ (or the admin review) | | ✅ |
| F10 reference protection | ✅ | | ✅ |
| F11 credentials in scripts | ✅ Re-Login and similar, Insert from URL | | partly |
| F13–F16 re-authentication, export, fmplugin, minimum version | ✅ | | ✅ |

Never ask for account passwords. Without ADK, nothing can read whether a password is blank, so
close the gap instead of testing it: the user sets a new strong password, in Manage > Security,
on every account whose password nobody can vouch for, starting with Admin, generic and
[Full Access] accounts. Report F4 as "not verified; closed by resetting" rather than as a pass.

## Checks per file

| # | Check | Pass | Why it matters |
|---|---|---|---|
| F1 | Guest account | Off | Guest opens the file with no password. The automated attacks try it first |
| F2 | Auto-login (File Options > Open > "Log in using") | Off | Anyone who reaches the file is signed in with a stored account, and nothing shows in failed sign-ins |
| F3 | Default and generic accounts (Admin, admin, web, user, api, test, guest, the file's own name) | None, or renamed with a strong unique password | These are the names password spraying tries |
| F4 | Blank or weak passwords | None | Every new file starts with an Admin account ([Full Access], no password) and auto-login as that account. Files that were never secured still have both |
| F5 | [Full Access] accounts | Few, named, never used by integrations | A sprayed [Full Access] account owns the file |
| F6 | Extended privileges on [Full Access] | Only `fmapp` and `fmreauthenticate10` (Claris, "Lock Down Your FileMaker Server", 4.1) | Stops the full-access account being used over the internet APIs, WebDirect, ODBC or URLs. `fmrest`, `fmodata` or `fmxml` on it is High; anything else, Medium |
| F7 | Extended privileges per privilege set | Only the ones the set uses (`fmapp`, `fmwebdirect`, `fmrest`, `fmodata`, `fmxdbc`, `fmxml`, `fmphp`, `fmurlscript`, `fmextscriptaccess`, `fmplugin`) | Each one is a door; unused ones stay shut. Claris's default privilege sets allow export and API access |
| F8 | Integration accounts | One per integration; a privilege set allowing only that API and its layouts; a long random password kept in a secrets manager and rotated; the calling system allow-listed (`exposure-check.md`); the account watched in the API logs | Limits what a leaked key can read. OAuth sign-in for the Data API and OData is browser-based, so these controls are what protect unattended integrations |
| F9 | Encryption at Rest | On for files with personal or sensitive data | A copied file or backup can't be opened without the key |
| F10 | "Require full access privileges to use references to this file" | On | Stops another file creating a reference to this one and reading through it |
| F11 | Credentials stored in scripts, custom functions or external data sources | None | Stored credentials work like auto-login |
| F12 | Unneeded files on the server | Removed | Every hosted file is a target |
| F13 | Re-authentication (`fmreauthenticate10`) in every set that accounts use | On | With the server's auto-logout for each client type (Admin Console), it disconnects or re-prompts idle users |
| F14 | Print and export | Only in the sets that need them | Data leaves the file there. A read-only set can still export every record it sees |
| F15 | `fmplugin` | Present and off; named plug-ins only (`fmplugin` plus the plug-in's four-character ID) where one is needed | Without it a plug-in can run scripts and SQL in the file from outside, and "require full access to use references" doesn't stop it. Files made before 19.2.1 don't have it: add it by hand. A generic `fmplugin` turned on admits every plug-in |
| F16 | Minimum client version (File > File Options > Open) | 21.0 or later, the oldest line still getting fixes | Keeps unsupported FileMaker versions from opening the file |

The server's own settings back these up: Filter databases, Deny Guest and auto-login, and
Secure files only (`server-config.md` S4–S6), and the Secure database folder (S16): an encrypted
file moved into the server's Secure folder refuses Guest and auto-login whatever the file says. They don't replace fixing the
file: Filter databases doesn't protect a file that allows Guest or auto-login.

### Guest as a short stopgap

If a file truly can't lose Guest for a few days, give Guest a custom privilege set: no printing
or exporting, minimal menus, and only the layouts it needs. Say plainly that this is a
stopgap: Guest with "read-only" access still hands every visible record to an attacker.

## External authentication

Signing file accounts in through an identity provider (OAuth: Microsoft Entra ID, Google, Okta,
or a Claris ID on FileMaker Cloud) ends password guessing against the file and brings the
provider's multi-factor authentication, location blocking and password management: today that's
how FileMaker gets two-factor sign-in. List the local FileMaker accounts that remain (developers,
integrations): they keep strong passwords, and [Full Access] keeps only `fmapp` and
`fmreauthenticate10`. Where the owner has an identity provider, recommend it.

## Replacing Guest and auto-login

People keep Guest or auto-login for two reasons: an anonymous WebDirect form (a link that opens
the right record), or a branded sign-in page instead of WebDirect's own. Neither needs them
(Claris, "Lock Down Your FileMaker Server", 6.3). Offer these when a finding is pushed back on:

| Need | Replacement |
|---|---|
| A branded sign-in with FileMaker accounts | A login page on the owner's own site that posts `user` and `pwd` to the WebDirect URL over HTTPS, with Custom Home URL (Connectors > Web Publishing, restart needed) sending people back to it on log-out. Harlow Technologies' fm-webdirect-custom is a starting point: use its form variant, and test it on the current version |
| A branded sign-in with OAuth | A sign-in button on the owner's site that starts the WebDirect OAuth flow, so people land in the file without WebDirect's sign-in screen (published guides on custom and seamless OAuth sign-in to WebDirect show how) |
| Anonymous public forms | A form provider feeding Claris Connect: either the on-premise agent pushes each submission through an outbound tunnel (no inbound port), or a schedule on the server pulls new submissions from an authenticated Connect webhook. The public never reaches FileMaker Server |
| Forms on the owner's own web server | A separate web server talks to the Data API with its own least-privilege account; FileMaker Server accepts traffic only from that server's address |
| Shrinking what's exposed | Nginx in a DMZ as the only machine on the internet, in front of a WebDirect worker and FileMaker Server, with path rules and rate limits (FileMaker Server 19.6+ load balancing) |

"Users won't log in eight times a day" is a session design problem, solved with re-authentication,
idle timeouts and single sign-on, not auto-login. Once replaced, move the files into the Secure
folder or turn on DenyGuestAndAutoLogin (`server-config.md` S5, S16), so they can't slip back.

## After changes, test

Make one test account per privilege set, run each through a short checklist (what it can open,
edit, delete, print and export, and through which client), write the results down, and repeat
after any change to a privilege set or a script it runs.

**Removing admin access.** Developer Utilities can remove [Full Access] from a deployed file
permanently (Solution Options > Remove admin access from files permanently), so nobody, attacker
included, can get developer access to it. It can't be undone: keep the original file, work on
a copy and test it before deploying. Mention it as an option for go-live, never as a finding.

"Don't display in host's file list" hides a file from the list only; nothing has to sign in
first, so a bot can still try it. It's obscurity, not a substitute for Filter databases.

## Passwords across servers

- Development, staging and test servers use different passwords from production. Test servers
  are usually less protected and leak first.
- Shared role accounts deployed to many customers or sites (a standard "teacher" or "staff"
  account in a vertical solution) need a different strong password at each site, so one leak
  doesn't open them all.
- Passwords typed on machines nobody controls (a customer's server, a shared PC) go on the
  rotation list.

## Severity

| Severity | Examples |
|---|---|
| Critical | Guest or auto-login on a file reachable from the internet; blank password on any account; `fmrest`/`fmodata` on [Full Access] with a guessable account name |
| High | Generic account names with any password; one role password shared across sites; dev and production sharing passwords |
| Medium | Unused extended privileges; anything but `fmapp` and `fmreauthenticate10` on [Full Access]; no re-authentication; no `fmplugin`, or the generic one on; a minimum client version below 21.0; no Encryption at Rest on sensitive files; references not restricted; auto-login set to an account that doesn't exist or is disabled (it starts working the moment someone creates or enables it) |
| Low | Unneeded files hosted but not reachable from outside |
