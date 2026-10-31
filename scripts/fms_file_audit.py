#!/usr/bin/env python3
"""FMS file audit: security settings inside FileMaker files, read from Save a Copy as XML.

Reads one SaXML export, or a folder of them (one per hosted file), and reports per file:
Guest, auto-login (File Options "Log in using"), generic and [Full Access] accounts,
extended privileges that open the Data API, OData and XML, Encryption at Rest, file
reference protection, passwords typed into scripts, and credentials in Insert from URL.

Needs no server connection, no credentials and no Claris ADT: only the exports. Make one
per file in FileMaker Pro with Tools > Save a Copy as XML (a [Full Access] account is
needed), or with the Save a Copy as XML script step, which also runs on FileMaker Server.

The report names accounts and scripts but never prints password hashes or script text.
The exports themselves hold password hashes and every script: keep them private.

Can't tell from SaXML: whether a password is blank or weak (only a salted hash is stored).

Usage:
    python3 fms_file_audit.py <file.xml or folder of .xml>
"""
import collections
import os
import re
import sys
import xml.etree.ElementTree as ET

GENERIC = {"admin", "administrator", "web", "webuser", "user", "api", "apiuser", "test", "guest",
           "filemaker", "demo", "dev", "developer", "sample"}
API_PRIVS = {"fmrest": "Data API", "fmodata": "OData", "fmxml": "XML", "fmphp": "PHP"}
WATCH_PRIVS = ["fmrest", "fmodata", "fmxml", "fmphp", "fmxdbc", "fmwebdirect", "fmurlscript"]
FULL = "[Full Access]"
# Elements that hold most of a file's bulk; cleared once read so large exports stream in
# bounded memory.
BULK = {"Layout", "Step", "Field", "TableOccurrence", "Relationship", "ValueList", "CustomFunction",
        "Theme", "LibraryCatalog", "CustomMenu"}
CRED_URL = re.compile(r"Authorization\s*:|--user\b|\s-u\s|Bearer\s|Basic\s", re.I)
LITERAL = re.compile(r'^\s*"[^"]+"\s*$')

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def text_of(el, path):
    found = el.find(path)
    return (found.text or "").strip() if found is not None else ""


def audit(path):
    info = dict(format="?", file=os.path.basename(path))
    accounts, privsets, extprivs = [], {}, {}
    login, encryption, refs_required = None, None, None
    pw_literals, url_creds, odbc = [], [], 0
    script_stack = []
    try:
        for event, el in ET.iterparse(path, events=("start", "end")):
            tag = el.tag
            if event == "start":
                if tag == "FMSaveAsXML":
                    info["format"] = el.get("version", "?")
                    info["file"] = el.get("File", info["file"])
                elif tag == "FileAccessCatalog":
                    refs_required = el.get("required")
                elif tag == "Script" and el.get("isFolder") != "True":
                    script_stack.append(el.get("name", "?"))
                continue
            if tag == "Account" and el.find("Authentication") is not None:
                ps = el.find("PrivilegeSetReference")
                accounts.append(dict(name=text_of(el, "Authentication/AccountName"),
                                     enabled=el.get("enable") == "True", type=el.get("type", "?"),
                                     privset=ps.get("name", "?") if ps is not None else "?"))
            elif tag == "PrivilegeSet" and el.find("access") is not None:
                other = el.find("access/Other")
                privsets[el.get("name", "?")] = dict(
                    print=other is not None and other.get("Print") == "True",
                    export=other is not None and other.get("Export") == "True")
            elif tag == "ExtendedPrivilege":
                extprivs[el.get("name", "?")] = [r.get("name", "?") for r in el.iter("PrivilegeSetReference")]
            elif tag == "Login" and login is None:
                login = dict(type=el.get("type"), account=text_of(el, "AccountName"))
            elif tag == "Encryption" and encryption is None:
                encryption = el.get("type")
            elif tag == "ExternalDataSource" and el.get("type", "FileMaker") != "FileMaker":
                odbc += 1
            elif tag == "Step":
                where = script_stack[-1] if script_stack else "?"
                for p in el.iter("Parameter"):
                    if p.get("type") == "Password":
                        t = text_of(p, "Calculation/Calculation/Text")
                        if LITERAL.match(t):
                            pw_literals.append(f'{el.get("name", "?")} in script "{where}"')
                if el.get("name") == "Insert from URL":
                    texts = " ".join((t.text or "") for t in el.iter("Text"))
                    if CRED_URL.search(texts) and re.search(r'"[^"]{6,}"', texts):
                        url_creds.append(f'script "{where}"')
            elif tag == "Script" and el.get("isFolder") != "True" and script_stack:
                script_stack.pop()
            if tag in BULK:
                el.clear()
    except ET.ParseError as e:
        return info, [("HIGH", "-", f"could not read the XML ({e}); re-export it")]

    f = []
    guest = next((a for a in accounts if a["name"].lower() == "[guest]"), None)
    if guest and guest["enabled"]:
        ps = guest["privset"]
        opens = [API_PRIVS[p] for p in API_PRIVS if ps in extprivs.get(p, [])]
        rights = privsets.get(ps, {})
        extra = "; can print/export" if rights.get("print") or rights.get("export") else ""
        f.append(("CRITICAL", "F1", f'Guest is ON with "{ps}"' + (f"; reachable via {', '.join(opens)}" if opens else "")
                  + extra))
    if login and login["type"] not in (None, "-1"):
        acct = login["account"] or "?"
        match = next((a for a in accounts if a["name"].lower() == acct.lower()), None)
        if match is None:
            f.append(("MEDIUM", "F2", f'auto-login is set to "{acct}", but no account has that name, so it '
                      "falls back to a sign-in prompt. Clear the setting before someone creates that account"))
        elif not match["enabled"]:
            f.append(("MEDIUM", "F2", f'auto-login is set to "{acct}", which is disabled. Clear the setting '
                      "before the account is re-enabled"))
        else:
            f.append(("CRITICAL" if match["privset"] == FULL or acct.lower() == "[guest]" else "HIGH", "F2",
                      f'auto-login is ON as "{acct}" ({match["privset"]}): anyone who reaches the file is signed in'))
    gen = sorted(a["name"] for a in accounts if a["enabled"] and a["name"].lower() in GENERIC)
    if gen:
        f.append(("HIGH", "F3", f"generic account names enabled: {', '.join(gen)}"))
    full = sorted(a["name"] for a in accounts if a["enabled"] and a["privset"] == FULL)
    f.append(("INFO" if len(full) <= 2 else "MEDIUM", "F5",
              f"{len(full)} enabled [Full Access] account(s): {', '.join(full[:8]) or 'none'}"))
    full_api = [API_PRIVS[p] for p in API_PRIVS if FULL in extprivs.get(p, [])]
    if full_api:
        f.append(("HIGH", "F6", f"[Full Access] can sign in over {', '.join(full_api)}; turn those off for it"))
    for p in WATCH_PRIVS:
        sets = [s for s in extprivs.get(p, []) if s != FULL]
        if sets:
            f.append(("INFO", "F7", f"{p} on for: {', '.join(sets[:8])}{' …' if len(sets) > 8 else ''}"))
    if encryption is not None:
        if encryption == "0":
            f.append(("MEDIUM", "F9", "not encrypted at rest"))
        else:
            f.append(("INFO", "F9", f"encryption type {encryption}: probably encrypted (unencrypted files export "
                      "as 0); the admin review's encryption check is authoritative"))
    if refs_required == "False":
        f.append(("MEDIUM", "F10", '"Require full access privileges to use references to this file" is off'))
    for p in pw_literals:
        f.append(("HIGH", "F11", f"password typed into {p}"))
    for u in url_creds:
        f.append(("MEDIUM", "F11", f"Insert from URL with credentials in {u}; check they aren't typed in"))
    if odbc:
        f.append(("INFO", "F11", f"{odbc} ODBC data source(s): check how their credentials are stored"))
    if not accounts:
        f.append(("HIGH", "-", "no accounts found: the export may be partial (check catalogs_included)"))
    return info, sorted(f, key=lambda x: ORDER.get(x[0], 9))


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    target = os.path.expanduser(sys.argv[1])
    if os.path.isdir(target):
        files = sorted(os.path.join(target, n) for n in os.listdir(target) if n.lower().endswith(".xml"))
    elif os.path.isfile(target):
        files = [target]
    else:
        sys.exit(f"Not found: {target}")
    totals = collections.Counter()
    print(f"##### FMS file audit: {len(files)} SaXML file(s)")
    for path in files:
        with open(path, "rb") as fh:
            if b"FMSaveAsXML" not in fh.read(2000):
                print(f"\n## {os.path.basename(path)}: not a Save a Copy as XML export, skipped")
                continue
        info, findings = audit(path)
        print(f"\n## {info['file']}  (SaXML format {info['format']})")
        for level, check, text in findings:
            totals[level] += 1
            print(f"  {level:8} {check:4} {text}")
    print("\n" + ", ".join(f"{totals[k]} {k}" for k in ORDER if totals[k]) +
          ". Not checked: blank or weak passwords (SaXML stores only a hash).")


if __name__ == "__main__":
    main()
