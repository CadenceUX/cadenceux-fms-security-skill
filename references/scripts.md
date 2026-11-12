# Scripts

Every script is run, not read, and needs only Python 3 (built into macOS and most Linux; on
Windows install it from python.org). `fms_scan.py` runs the first five checks below in one go;
run one on its own only to re-check that part.

| Script | What it does |
|---|---|
| `scripts/fms_scan.py` | One command for the automated checks: exposure, services, published issues and the log review. Saves each full output, writes `findings.json` and `report-draft.md`, and prints a short summary (also `summary.txt`) |
| `scripts/fms_exposure_check.py` | TCP connect to the 82 ports in `references/ports.json`, HTTP-to-HTTPS redirect, TLS certificate, HSTS and old TLS checks, unauthenticated GET of the FileMaker web paths, FileMaker Server's version from the Data API's product information, and what each open port says it is (through `fms_service_scan.py`). `--services-json` saves the services for the next script |
| `scripts/fms_service_scan.py` | Loaded by the exposure check: reads each open port's greeting, web headers, VNC security types, or the first NTLM answer from Remote Desktop and SMB. Never signs in |
| `scripts/fms_service_advisories.py` | Published issues for the services found: Ubuntu packages against Ubuntu's security data (through OSV.dev), other versions against NVD by CPE, and the operating system's support from `references/os-lifecycle.json`. Sends only product names and versions |
| `scripts/fms_advisories.py` | FileMaker CVEs live from NVD (one request), merged with Claris release-note fixes from `references/advisories.json`, for a given FileMaker Server version (or FileMaker Pro, with `--pro`). Falls back to the bundled list offline and says how old it is |
| `scripts/fms_logcheck.py` | Reads a Logs folder or zip: new addresses, client builds with published issues, flagged failed sign-ins, addresses that failed and also signed in, ODBC/JDBC connections, admin sign-ins, settings and file events, Admin API errors, record download bursts, web-server requests. `--brief` keeps the output short; `--save <file>` writes the full output too |
| `scripts/fms_admin_review.py` | Run **by the user** in their own terminal: signs in to the Admin API, reads version, certificate, secure files, Admin Console restriction, Filter databases, services, per-file API privileges and encryption, connected Guest sessions, admin roles, schedules, plug-ins and Perform Script on Server sessions (GET only), signs out. A program that has already signed in can pass its token with `--token-stdin` |
| `scripts/fms_file_audit.py` | Reads Save a Copy as XML exports, no server connection: Guest, auto-login, generic and [Full Access] accounts, extended privileges, Encryption at Rest, reference protection, passwords typed into scripts, credentials in Insert from URL. Never prints hashes or script text |
| `scripts/fms_findings.py` | A module, not run: turns the checks' output into findings. `fms_scan.py` uses it, and so can any program that runs these checks, so a finding reads the same in each. `references/finding-templates.json` gives each finding its priority, title, why and what to do |

`test_service_scan.py` is the service checks' own tests.
