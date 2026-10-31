# If a server is under attack

Contain first, preserve evidence, then investigate. Work in this order.

## 1. Stop new connections (minutes)

1. **Block New Users** in the Admin Console. Existing sessions keep working; nobody new can
   connect.
2. **Block port 443 at the firewall** except for known addresses, or turn off the Data API,
   OData and XML connectors if no one needs them right now.
3. **Close any hosted file that uses Guest or auto-login.** Those sign in with no password, so
   they are the easiest way in.
4. Block the attacking addresses, knowing that this campaign rotates addresses.

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
form service, or a CSV export and import) keeps the work going. The lasting design is a separate
front-end that collects submissions, so the public never connects to FileMaker directly.
