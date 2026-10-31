# File security review

Review **every hosted file**, not only the main solution: deployment tools, utility files,
sample files and old copies are hosted on the same server and accept the same attacks. Files
that nobody needs should be closed and removed from the server.

## Contents
- How to read the settings
- Checks per file
- Passwords across servers
- Severity

## How to read the settings

**No extra tools are needed.** The default route uses only FileMaker Pro and Python. Claris ADT
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
   privileges by privilege set, Encryption at Rest, reference protection, passwords typed into
   script steps, and credentials in Insert from URL. The exports hold password hashes and every
   script, so scan them locally, never upload them, and delete them when the review is done.
2. **ADT, only if already installed.** It adds the one thing SaXML can't show: whether an
   account has a password at all (blank passwords). Use the `fm-cli` skill and `filemaker help
   account` for the exact read command; it reaches hosted files over `fmnet://` and signs in
   with ADT's own stored credentials, never a password typed into the chat.
3. **Guided**, when neither is possible: ask the user to open each file with a [Full Access]
   account and report or screenshot **Manage > Security** (accounts, privilege sets, extended
   privileges) and **File > File Options** (the Open tab). One file at a time.

| Check | SaXML audit | ADT (optional) | Guided |
|---|---|---|---|
| F1 Guest, F2 auto-login, F3 generic names, F5 [Full Access] count | ✅ | ✅ | ✅ |
| F4 blank passwords | ❌ hash only | ✅ `hasPassword` | ✅ user checks |
| F6–F7 extended privileges | ✅ | ✅ | ✅ |
| F9 Encryption at Rest | ✅ (or the admin review) | | ✅ |
| F10 reference protection | ✅ | | ✅ |
| F11 credentials in scripts | ✅ Re-Login and similar, Insert from URL | | partly |

Never ask for account passwords. Without ADT, nothing can read whether a password is blank, so
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
| F6 | Extended privileges on [Full Access] | `fmrest`, `fmodata`, `fmxml` off | Stops the full-access account being used over the internet APIs |
| F7 | Extended privileges per privilege set | Only the ones the set uses (`fmapp`, `fmwebdirect`, `fmrest`, `fmodata`, `fmxdbc`, `fmxml`, `fmphp`, `fmurlscript`, `fmextscriptaccess`, `fmplugin`) | Each one is a door; unused ones stay shut. Claris's default privilege sets allow export and API access |
| F8 | Integration accounts | One per integration, its own privilege set, only its layouts | Limits what a leaked key can read |
| F9 | Encryption at Rest | On for files with personal or sensitive data | A copied file or backup can't be opened without the key |
| F10 | "Require full access privileges to use references to this file" | On | Stops another file creating a reference to this one and reading through it |
| F11 | Credentials stored in scripts, custom functions or external data sources | None | Stored credentials work like auto-login |
| F12 | Unneeded files on the server | Removed | Every hosted file is a target |

The server's own settings back these up: Filter databases, Deny Guest and auto-login, and
Secure files only (`server-config.md` S4–S6). They don't replace fixing the
file: Filter databases doesn't protect a file that allows Guest or auto-login.

### Guest as a short stopgap

If a file truly can't lose Guest for a few days, give Guest a custom privilege set: no printing
or exporting, minimal menus, and only the layouts it needs. Say plainly that this is a
stopgap: Guest with "read-only" access still hands every visible record to an attacker.

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
| Medium | Unused extended privileges; no Encryption at Rest on sensitive files; references not restricted; auto-login set to an account that doesn't exist or is disabled (it starts working the moment someone creates or enables it) |
| Low | Unneeded files hosted but not reachable from outside |
