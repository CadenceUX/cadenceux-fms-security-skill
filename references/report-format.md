# Report format

The default report is written for the person who owns the server, not for a FileMaker
specialist: tables, plain English, one action per row. Save it as a Markdown file in the user's
working folder (or put it in the reply where no files can be written), named
`FMS security check - <server> - <YYYY-MM-DD>.md`.

## Contents
- Rules
- Template
- Priority labels
- Writing the rows

## Rules

- **Plain English.** Say what someone could do, not the setting's internal name: "anyone can
  see your file names without signing in", not "databaseVisibility false".
- **One finding per row, one action per finding.** Put the menu path in the action; put
  commands only in the "For your FileMaker administrator" section.
- **Every row has an owner** (the user, their FileMaker developer, their hosting provider, IT)
  and a status (Open, Fixed, Accepted).
- **Show what passed.** A report of only problems reads as worse than the server is.
- **Say what wasn't checked**, and why. Never imply a step that didn't run was a pass.
- **Date the evidence**: which logs and dates, and the date of the advisory data.
- Keep the private note at the top: the report names accounts, addresses and weaknesses.
- Keep the limits note under it: one skill, as is, not a professional assessment.
- **Recovery readiness is the owner's call.** Fill the expectations column with the data
  owner's own answers from intake; where there are none, write "To agree with the owner".

## Template

```markdown
# FileMaker Server security check

> **Private.** This report names accounts, addresses and weaknesses. Don't publish or forward it.
>
> **Limits.** This report comes from one skill, cadenceux-fms-security: a set of automated checks,
> offered as is, with no guarantee or support. It doesn't replace a security assessment by
> professionals.

| | |
|---|---|
| **Server** | <name and where it runs> |
| **Checked** | <date>, from <where the exposure check ran> |
| **Result** | <🟢 No sign of attack / 🟠 Attempted attack / 🔴 Possible compromise> |
| **To fix** | <n> Critical · <n> High · <n> Medium · <n> Low |

## What to fix

| # | Priority | What we found | Why it matters | What to do | Owner | Status |
|---|---|---|---|---|---|---|
| 1 | 🟠 High | ... | ... | ... | ... | Open |

## Recovery readiness

| | The owner expects | Today | Gap | What to do | Owner |
|---|---|---|---|---|---|
| **Data loss** | <e.g. at most 1 hour> | <backup interval> | ... | ... | ... |
| **Down time** | <e.g. back within 4 hours> | <last test restore and how long it took, or "never tested"> | ... | ... | ... |
| **Clean copy** | One copy beyond the server's network | <where the copies go> | ... | ... | ... |
| **DR plan** | Written and agreed with the owner | <yes / no> | ... | ... | ... |

Every gap here is also a row in "What to fix", with its priority, owner and status.

## What passed

| Check | Result |
|---|---|
| ... | ✅ ... |

## Staff computers to update

| FileMaker Pro version | Machines | Issue | Update to |
|---|---|---|---|

(or "None: no client version with a published issue connected.")

## Not checked

| What | Why | How to cover it |
|---|---|---|

## Next steps

1. <the one or two fixes that matter most>
2. <where no DR plan is agreed: agree how much data the owner can lose and how long they can be
   down, and write it down>
3. Re-run the check after fixing, to confirm.
4. <log check schedule>

## For your FileMaker administrator

<commands, script output references, log dates, advisory data date: the technical detail
the table leaves out>
```

## Priority labels

| Label | Meaning | Use for |
|---|---|---|
| 🔴 Critical | Fix today | Data can be read or the server taken over now (definitions in each reference) |
| 🟠 High | Fix this week | One step from Critical, or a published issue with CVSS 7+ on the server |
| 🟡 Medium | Plan it | Weakens defences but needs something else to go wrong first |
| ⚪ Low | When convenient | Tidy-up and information disclosure |
| 🔵 Check | Needs a look | Something the check saw but can't judge |

Order rows Critical, High, Medium, Check, Low.

## Writing the rows

| Column | Good | Too technical |
|---|---|---|
| What we found | "Anyone who can reach the server can see the name of your data file without signing in" | "fmclients/databasevisibility = false" |
| Why it matters | "Attack tools start by listing your files, then try to open each one" | "Enables enumeration" |
| What to do | "Admin Console > Configuration > FileMaker Clients: turn on Filter databases" | "PATCH databasevisibility" |
