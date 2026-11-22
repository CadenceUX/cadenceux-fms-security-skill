# If a server is under attack

Contain first, preserve evidence, then investigate. Work in this order.

## 0. Open the DR plan (alongside step 1, never instead of it)

Find the Disaster Recovery plan and the recovery expectations from intake. How long the owner
can be down decides when to move users to a DR server or a temporary intake, and the plan says
who to call. With no plan, tell the owner what containment cuts off as you do it. Never let a
missing plan delay containment.

## 1. Stop new connections (minutes)

1. **Block New Users** in the Admin Console. Existing sessions keep working; nobody new can
   connect.
2. **Block ports 443 and 2399 at the firewall** except for known addresses, or turn off the Data
   API, OData, XML and ODBC/JDBC connectors if no one needs them right now.
3. **Close any hosted file that uses Guest or auto-login.** Those sign in with no password, so
   they are the easiest way in. To keep the rest of the server running while they're shut out:
   turn on `DenyGuestAndAutoLogin` for the whole server (`fmsadmin set serverprefs
   DenyGuestAndAutoLogin=true`), or, file by file, turn on Encryption at Rest and move the file
   into the server's Secure database folder, which refuses Guest and auto-login for it. Either
   way, whatever depends on Guest or auto-login stops until it's replaced.
4. Block the attacking addresses, knowing that this campaign rotates addresses.
   **Check the server-side plug-ins** too: some run operating-system commands. If nothing
   server-side needs them, set all three engines to Disabled under Connectors > Plug-ins
   (Web Publishing and the Data API need restarts), and remove unused plug-ins from all three
   plug-in folders.
5. **Disconnect the attacker's open sessions** (Admin Console > Clients). Block New Users leaves
   sessions already connected running.

Steps 1 and 2 also cut off WebDirect users and integrations. Tell the people affected.

## 2. Preserve evidence (before anything restarts)

- Copy the whole Logs folder and the web-server access log off the server now. The web-server
  log may hold only the current day, and Access.log rolls over by size.
- Note the time, the time zone, and every action taken.
- Don't restart, upgrade or reinstall until the copies are safe.

## 3. Work out what was read

Run the log check from the earliest log date. For each unknown address that signed in: which
account, which files, which layouts, how many records. Treat every field on a layout the
attacker reached as exposed.

## 4. Fix and recover

- **Choose the restore point.** If files need restoring, use a backup from before the earliest
  activity from the attacker's addresses. Check the earlier logs for reconnaissance and other
  unknown addresses first: it can come days before the first sign-in. A backup taken after the
  attacker got in may hold changed accounts, scripts or data. If the backups sit where the
  server could write to them, check they weren't altered or deleted.
- **Weigh the gap.** Records entered since that backup need recovering or re-entering. Show the
  owner the gap against the data loss they said they could bear, and agree how to fill it.
- **Restore onto a fixed server.** Restoring files alone leaves the same way in: close the gaps
  below before anyone reconnects. A file restore doesn't roll back server settings either:
  check Event.log for settings, schedule and plug-in changes made from the attacker's addresses,
  and reverse them. Run the file audit on the restored copies before anyone uses them.
- Rotate every password and key that touches the server: file accounts, Admin Console, Admin
  API keys held by management tools or hosting providers, and integration credentials.
- Remove Guest and auto-login, generic accounts, and unneeded extended privileges
  (`file-security.md`).
- Restrict the Admin Console and APIs by IP before reopening.
- Re-run the exposure check and the log check before lifting Block New Users.

## 5. Notify

If personal data may have been read, involve whoever owns privacy and legal for the
organisation now: breach-notification deadlines can run from the moment the exposure is known.
Name the user's own jurisdiction's scheme (for example the Notifiable Data Breaches scheme in
Australia or GDPR in the EU) rather than assuming one.

## If something has to stay offline

If a public form or portal has to stay closed while it's fixed, a temporary intake (a hosted
form service, or a CSV export and import) keeps the work going. Work back from the cost: what an
hour, a day or a week offline costs decides how much effort the fallback deserves. A hosted form
service holds the submissions at a third party, so know what it keeps.

The lasting design never needs Guest or auto-login: a branded sign-in page posting to WebDirect,
an OAuth sign-in from the owner's own site, or a form provider feeding Claris Connect, so the
public never connects to FileMaker directly (`file-security.md`, Replacing Guest and auto-login).
