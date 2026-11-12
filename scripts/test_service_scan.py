#!/usr/bin/env python3
"""Tests for the outside-in service scan: the greeting parsers, the NTLM reader, the OS guess, the version
comparisons and the advisory matching. No network: lookups get recorded answers. Every hostname and name here is
made up.

    python3 test_service_scan.py
"""
import importlib.util
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


svc, adv, exp = load("fms_service_scan"), load("fms_service_advisories"), load("fms_exposure_check")
LIFE = json.load(open(os.path.join(HERE, "..", "references", "os-lifecycle.json"), encoding="utf-8"))
results = []


def check(name, ok):
    ok = bool(ok)
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name)


# ---- SSH ----
s = svc.parse_ssh(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
check("ssh: Ubuntu package gives release, codename and full package version",
      (s["product"], s["version"], s["os"], s["os_release"], s["codename"], s["package_version"]) ==
      ("OpenSSH", "8.9p1", "Ubuntu", "22.04", "jammy", "1:8.9p1-3ubuntu0.10"))
check("ssh: an Ubuntu package isn't matched by NVD version", s["matchable"] is False and s["cpe"].endswith(":openssh:8.9"))
s = svc.parse_ssh(22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")
check("ssh: Debian package gives release 12 and a caveat", s["os"] == "Debian" and s["os_release"] == "12" and "Debian" in s["note"])
s = svc.parse_ssh(22, "SSH-2.0-OpenSSH_9.6p1")
check("ssh: plain OpenSSH is matched by version, no OS", s["matchable"] and not s["os"] and s["cpe"] == "cpe:2.3:a:openbsd:openssh:9.6")
s = svc.parse_ssh(22, "SSH-2.0-OpenSSH_for_Windows_8.1")
check("ssh: OpenSSH for Windows names Windows", s["os"] == "Windows" and s["version"] == "8.1")
s = svc.parse_ssh(22, "SSH-2.0-dropbear_2022.83")
check("ssh: Dropbear", s["product"] == "Dropbear SSH" and s["version"] == "2022.83")
check("ssh: an Ubuntu release the scan doesn't know is said plainly",
      "can't be checked" in svc.parse_ssh(22, "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6")["note"])

# ---- Web ----
w = svc.parse_web(443, "nginx/1.24.0 (Ubuntu)", tls=True)[0]
check("web: nginx (Ubuntu) is a package, not matched by version", w["product"] == "nginx" and w["os"] == "Ubuntu" and not w["matchable"])
w = svc.parse_web(80, "Microsoft-IIS/10.0")[0]
check("web: IIS names Windows and isn't matched (10.0 says nothing)", w["os"] == "Windows" and not w["matchable"] and "2016" in w["note"])
ws = svc.parse_web(80, "Apache/2.4.41 (Unix) OpenSSL/1.1.1k PHP/7.4.3")
check("web: every product in an Apache header is read", [x["product"] for x in ws] == ["Apache HTTP Server", "OpenSSL", "PHP"])
check("web: Apache upstream build is matched", ws[0]["matchable"] and ws[0]["cpe"] == "cpe:2.3:a:apache:http_server:2.4.41")
w = svc.parse_web(80, "nginx", "PHP/8.1.2-1ubuntu2.14")
check("web: X-Powered-By PHP with an Ubuntu build isn't matched", w[1]["product"] == "PHP" and not w[1]["matchable"])
check("web: nginx without a version says so", w[0]["note"] == "no version shown")
w = svc.parse_web(7000, "AirTunes/1005.13.5")[0]
check("web: AirPlay Receiver names macOS", w["os"] == "macOS" and "AirPlay" in w["product"])
check("web: Microsoft-HTTPAPI names Windows", svc.parse_web(5985, "Microsoft-HTTPAPI/2.0")[0]["os"] == "Windows")

# ---- FTP, mail ----
f = svc.parse_ftp(21, "220 (vsFTPd 3.0.5)\r\n")
check("ftp: vsftpd version", f["product"] == "vsftpd" and f["version"] == "3.0.5" and f["matchable"])
check("ftp: Microsoft FTP names Windows", svc.parse_ftp(21, "220 Microsoft FTP Service")["os"] == "Windows")
m = svc.parse_mail(25, "220 mail.example.com ESMTP Postfix (Ubuntu)", "smtp")
check("mail: Postfix (Ubuntu)", m["product"] == "Postfix" and m["os"] == "Ubuntu")
m = svc.parse_mail(25, "220 mx.example.com ESMTP Exim 4.96 Tue, 10 Nov 2026", "smtp")
check("mail: Exim version is matched", m["product"] == "Exim" and m["version"] == "4.96" and m["matchable"])
check("mail: Exchange names Windows",
      svc.parse_mail(25, "220 ex.example.com Microsoft ESMTP MAIL Service ready", "smtp")["os"] == "Windows")
check("mail: Dovecot (Ubuntu) over IMAP", svc.parse_mail(143, "* OK [CAPABILITY IMAP4rev1] Dovecot (Ubuntu) ready.", "imap")["os"] == "Ubuntu")

# ---- MySQL ----
def mysql_packet(version):
    body = b"\x0a" + version.encode() + b"\x00" + b"\x01\x00\x00\x00" + b"abcdefgh\x00"
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


my = svc.parse_mysql(3306, mysql_packet("8.0.36-0ubuntu0.22.04.1"))
check("mysql: Ubuntu build names Ubuntu 22.04", my["product"] == "MySQL" and my["version"] == "8.0.36" and my["os_release"] == "22.04")
my = svc.parse_mysql(3306, mysql_packet("5.5.5-10.11.6-MariaDB-0+deb12u1"))
check("mysql: MariaDB behind the 5.5.5- prefix, Debian", my["product"] == "MariaDB" and my["version"] == "10.11.6" and my["os"] == "Debian")
err = b"\x45\x00\x00\x00\xff\x6a\x04Host '203.0.113.9' is not allowed to connect to this MySQL server"
check("mysql: a refusal is reported, not a version", "refuses" in svc.parse_mysql(3306, err)["note"])

# ---- VNC ----
v = svc.parse_rfb(5900, "RFB 003.889\n", [30, 2])
check("vnc: Apple's RFB 003.889 is macOS Screen Sharing", v["product"] == "macOS Screen Sharing" and v["os"] == "macOS")
v = svc.parse_rfb(5900, "RFB 003.008\n", [1])
check("vnc: security type 1 means no password", v.get("no_auth") and "NO PASSWORD" in v["note"])
check("vnc: Apple security types without Apple's version still say macOS", svc.parse_rfb(5900, "RFB 003.008\n", [35])["os"] == "macOS")


# ---- NTLM ----
def challenge(major, minor, build, pairs):
    info = b"".join(struct.pack("<HH", k, len(v.encode("utf-16-le"))) + v.encode("utf-16-le") for k, v in pairs) + b"\x00\x00\x00\x00"
    head = (b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56) + struct.pack("<I", 0x02880205)
            + b"\x11" * 8 + b"\x00" * 8 + struct.pack("<HHI", len(info), len(info), 56)
            + bytes([major, minor]) + struct.pack("<H", build) + b"\x00\x00\x00\x0f")
    return b"\x30\x82junk" + head + info


blob = challenge(10, 0, 20348, [(1, "FILESRV"), (2, "EXAMPLE"), (4, "example.lan")])
n = svc.parse_ntlm_challenge(blob)
check("ntlm: version and names read from a CHALLENGE inside other bytes",
      (n["major"], n["minor"], n["build"]) == (10, 0, 20348) and n["names"] == {"netbios_computer": "FILESRV", "netbios_domain": "EXAMPLE", "dns_domain": "example.lan"})
r = svc.windows_service(3389, "Windows Remote Desktop", n, LIFE)
check("ntlm: build 20348 is Windows Server 2022", r["os"] == "Windows" and r["os_release"] == "Windows Server 2022")
check("ntlm: the names given away are noted", "FILESRV" in r["note"] and "example.lan" in r["note"])
mac = svc.windows_service(445, "SMB file sharing", svc.parse_ntlm_challenge(challenge(6, 1, 7600, [(1, "STUDIO-MAC"), (4, "local")])), LIFE)
check("ntlm: 6.1.7600 is a placeholder, and .local points to macOS", mac["os"] == "macOS" and mac.get("os_weak") and "placeholder" in mac["note"])
check("ntlm: build 0 is a placeholder, not Windows", svc.windows_service(445, "SMB", svc.parse_ntlm_challenge(challenge(6, 1, 0, [])), LIFE)["os"] == "")
check("ntlm: an unknown build keeps its number", svc.windows_service(3389, "RDP", svc.parse_ntlm_challenge(challenge(10, 0, 30000, [])), LIFE)["os_release"] == "build 10.0.30000")
check("ntlm: no CHALLENGE, no answer", svc.parse_ntlm_challenge(b"nothing here") is None)
neg = svc.ntlm_negotiate()
check("ntlm: NEGOTIATE asks for the version", neg.startswith(b"NTLMSSP\x00\x01\x00\x00\x00") and struct.unpack_from("<I", neg, 12)[0] & 0x02000000)
ts = svc.credssp_negotiate()
check("credssp: TSRequest is one well-formed DER SEQUENCE carrying the NEGOTIATE", ts[0] == 0x30 and ts[1] == len(ts) - 2 and neg in ts)
hdr = svc.smb2_header(1, 1)
check("smb: SMB2 header is 64 bytes", len(hdr) == 64 and hdr.startswith(b"\xfeSMB"))

# ---- OS guess ----
both = [svc.parse_web(80, "nginx/1.18.0 (Ubuntu)")[0], r]
o = svc.best_os(both)
check("os: a Windows build beats a header tag, and the disagreement is kept",
      o["name"] == "Windows" and o["release"] == "Windows Server 2022" and not o["agree"] and o["others"] == ["Ubuntu"])
check("os: label doesn't repeat Windows", svc.os_label("Windows", "Windows Server 2022") == "Windows Server 2022"
      and svc.os_label("Ubuntu", "22.04") == "Ubuntu 22.04")
check("os: nothing named, nothing guessed", svc.best_os([svc.service(5003, "FileMaker Server")])["name"] == "")

# ---- Version comparison ----
dc = adv.dpkg_compare
check("dpkg: Ubuntu revisions in order", dc("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.18") < 0 and dc("1:8.9p1-3ubuntu0.18", "1:8.9p1-3ubuntu0.18") == 0)
check("dpkg: ~ sorts before the release", dc("1.0~rc1", "1.0") < 0)
check("dpkg: numbers compare as numbers", dc("2.30", "2.4") > 0)
check("dpkg: epoch wins", dc("1:1.0", "2.0") > 0)
check("dpkg: an ESM build is newer than the plain one", dc("1:8.2p1-4ubuntu0.13+esm1", "1:8.2p1-4ubuntu0.13") > 0)
uk = adv.upstream_key
check("upstream: 8.9 < 8.9p1 < 9.8p1 and 2.4.6 < 2.4.58", uk("8.9") < uk("8.9p1") < uk("9.8p1") and uk("2.4.6") < uk("2.4.58"))
rng = {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "vulnerable": True, "versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}
check("range: 9.6p1 is inside 8.5p1 to 9.8p1, 9.8p1 isn't", adv.in_range(rng, "9.6p1") and not adv.in_range(rng, "9.8p1"))
check("range: an exact version with an update", adv.in_range({"criteria": "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"}, "8.9p1")
      and not adv.in_range({"criteria": "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"}, "8.8p1"))
check("range: every version with no bounds isn't counted", not adv.in_range({"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}, "9.6p1"))


# ---- NVD and Ubuntu matching, with recorded answers ----
def nvd_cve(cid, score, matches):
    return {"cve": {"id": cid, "published": "2026-01-01T00:00:00", "descriptions": [{"lang": "en", "value": cid + " text. More."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                    "configurations": [{"nodes": [{"cpeMatch": matches}]}]}}


nvd_page = {"totalResults": 3, "resultsPerPage": 3, "vulnerabilities": [
    nvd_cve("CVE-2026-0001", 8.1, [rng]),
    nvd_cve("CVE-2026-0002", 5.0, [{"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "9.9"},
                                   {"criteria": "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", "vulnerable": False}]),
    nvd_cve("CVE-2026-0003", 9.8, [dict(rng, versionEndExcluding="9.0")])]}
asked = []
got = adv.nvd_issues("cpe:2.3:a:openbsd:openssh:9.6", "9.6p1", get=lambda url: asked.append(url) or nvd_page)
check("nvd: only CVEs listing this product version as vulnerable", [i["id"] for i in got] == ["CVE-2026-0001"] and got[0]["severity"] == "High")
check("nvd: the request carries product and version only", "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A9.6" in asked[0]
      and "example" not in asked[0])


def ub(cid, status, desc="", score=7.0):
    return {"id": cid, "published": "2026-02-01", "cvss3": score, "priority": "medium", "description": cid + "\nwrapped. More.",
            "packages": [{"name": "openssh", "statuses": [{"release_codename": "jammy", "status": status, "description": desc},
                                                          {"release_codename": "noble", "status": "needed", "description": ""}]}]}


pages = {0: {"total_results": 25, "cves": [ub("CVE-A", "released", "1:8.9p1-3ubuntu0.18"), ub("CVE-B", "released", "1:8.9p1-3ubuntu0.4"),
                                          ub("CVE-C", "needed"), ub("CVE-D", "not-affected")] + [ub(f"CVE-N{i}", "not-affected") for i in range(16)]},
         20: {"total_results": 25, "cves": [ub("CVE-E", "needs-triage"), ub("CVE-F", "deferred", "2026-10-29", None)]}}
urls = []
adv.time.sleep = lambda s: None
issues, fixed, untriaged = adv.ubuntu_issues("openssh", "jammy", "1:8.9p1-3ubuntu0.10",
                                             get=lambda url: urls.append(url) or pages[int(url.rsplit("offset=", 1)[1])])
ids = {i["id"]: i for i in issues}
check("ubuntu: a newer fixed package is open, an older one counts as fixed", "CVE-A" in ids and "CVE-B" not in ids and fixed == 1)
check("ubuntu: needed and deferred are open, not-affected skipped, untriaged counted",
      ids["CVE-C"]["status"] == "no Ubuntu fix yet" and ids["CVE-F"]["status"] == "Ubuntu deferred the fix" and "CVE-D" not in ids and untriaged == 1)
check("ubuntu: pages through 20 at a time", len(urls) == 2 and "limit=20" in urls[0])
check("ubuntu: summaries are one line", "\n" not in ids["CVE-A"]["summary"])

# ---- OS support ----
sup = lambda name, rel: adv.os_support({"name": name, "release": rel}, LIFE, today="2026-11-12")["state"]
check("support: Windows Server 2012 R2 is out", sup("Windows", "Windows Server 2012 R2 or Windows 8.1") == "unsupported")
check("support: Windows Server 2022 is in", sup("Windows", "Windows Server 2022") == "supported")
check("support: Ubuntu 20.04 needs Ubuntu Pro, 22.04 is in, 18.04 standard is out", sup("Ubuntu", "20.04") == "esm"
      and sup("Ubuntu", "22.04") == "supported" and sup("Ubuntu", "18.04") == "esm")
check("support: Debian 11 is out, 12 is on LTS", sup("Debian", "11") == "unsupported" and sup("Debian", "12") == "esm")
check("support: macOS's release can't be seen", sup("macOS", "") == "unknown")

# ---- Exposure check ----
ports = exp.load_ports()
check("ports: 82 ports, FileMaker's first, none twice", len(ports) == 82 and list(ports)[:3] == [80, 443, 5003])
check("ports: every non-FileMaker expectation marks an open port for review",
      all(e.startswith(("should", "close")) for p, (w, e) in ports.items() if p not in (80, 443, 5003)))
check("fms version: read from productInfo", exp.fms_version('{"response":{"productInfo":{"name":"FileMaker Data API Engine","version":"26.0.3.309"}}}') == "26.0.3.309")
check("fms version: nothing from a non-JSON page", exp.fms_version("<html>") == "")
# A program reading this output with these patterns must never mistake a Services line for an open port or a web finding
import re
PORT = re.compile(r"^  (\d+)\s+OPEN\s+(.*?)\s+\[(.*?)\]\s+<-- review")
WEB = re.compile(r"^  (\S+)\s+(/\S*)\s+(.*?)\s+<-- (.*)$")
lines = [f"  {x['port']:<6} {svc.describe(x)}" for x in [mac, v, svc.parse_ssh(22, "SSH-2.0-OpenSSH_9.6p1"), w]]
check("report: Services lines don't match the port or web patterns", not any(PORT.match(l) or WEB.match(l) for l in lines))

# CVSS 3.1 base scores from vectors, against scores NVD publishes
c3 = adv.cvss3_score
check("cvss: vectors give NVD's scores, unchanged and changed scope",
      c3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8 and c3("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N") == 6.8
      and c3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1 and c3("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N") == 4.3
      and c3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0 and c3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0)
check("cvss: a vector that can't be read gives None", c3("CVSS:3.1/AV:N") is None and c3("nonsense") is None)
# OSV: a recorded reply's shape, with made-up CVE numbers
def osv_vuln(cve, prio, vectors, fixes, upstream=True):
    return {"id": "UBUNTU-" + cve, "published": "2026-01-02T00:00:00Z", "details": f"{cve} lets someone in. More text.",
            **({"upstream": [cve]} if upstream else {}),
            "severity": [{"type": "CVSS_V3", "score": v} for v in vectors] + [{"type": "Ubuntu", "score": prio}],
            "affected": [{"package": {"ecosystem": eco, "name": "openssh"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}] + ([{"fixed": f}] if f else [])}]}
                         for eco, f in fixes]}
J, P = "Ubuntu:22.04:LTS", "Ubuntu:Pro:22.04:LTS"
seen_q = []
def osv_get(url, body=None):
    seen_q.append(body)
    if body.get("page_token") is None:
        return {"vulns": [osv_vuln("CVE-2099-0001", "high", ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], [(J, "1:8.9p1-3ubuntu0.18")]),
                          osv_vuln("CVE-2099-0002", "medium", [], [(J, "")]),
                          osv_vuln("CVE-2099-0005", "negligible", [], [(J, "")]),
                          osv_vuln("CVE-2099-0006", "low", ["CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], [(J, "1:8.9p1-3ubuntu0.11")]),
                          {"id": "USN-9999-1", "affected": []},
                          osv_vuln("CVE-2099-0003", "low", ["CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N"], [(J, "1:8.9p1-3ubuntu0.9")])],
                "next_page_token": "p2"}
    return {"vulns": [osv_vuln("CVE-2099-0004", "medium", [], [(J, ""), (P, "1:8.9p1-3ubuntu0.10+esm1")], upstream=False)]}
oi, _, _ = adv.osv_ubuntu_issues("openssh", "jammy", "1:8.9p1-3ubuntu0.10", osv_get)
byid = {i["id"]: i for i in oi}
check("osv: asks by package, Ubuntu ecosystem and installed version, and follows the next page",
      seen_q[0] == {"package": {"name": "openssh", "ecosystem": J}, "version": "1:8.9p1-3ubuntu0.10"} and seen_q[1]["page_token"] == "p2")
check("osv: keeps Ubuntu's CVE records, drops the USN notices, anything this version already fixes, and unfixed negligible ones",
      sorted(byid) == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004", "CVE-2099-0006"])
check("osv: the score is Ubuntu's own, the first vector, not the reporter's higher one",
      byid["CVE-2099-0006"]["cvss"] == 4.3 and byid["CVE-2099-0006"]["severity"] == "Medium")
check("osv: score from the CVSS vector, else Ubuntu's priority",
      byid["CVE-2099-0001"]["cvss"] == 9.8 and byid["CVE-2099-0001"]["severity"] == "Critical"
      and byid["CVE-2099-0002"]["cvss"] is None and byid["CVE-2099-0002"]["severity"] == "Medium")
check("osv: fixed, not yet fixed, and fixed only in Ubuntu Pro",
      byid["CVE-2099-0001"]["fixed"] == "1:8.9p1-3ubuntu0.18" and byid["CVE-2099-0002"]["status"] == "no Ubuntu fix yet"
      and byid["CVE-2099-0004"]["status"] == "fixed only in Ubuntu Pro" and byid["CVE-2099-0004"]["fixed"] == "1:8.9p1-3ubuntu0.10+esm1")
check("osv: worst first, summary is the first sentence", oi[0]["id"] == "CVE-2099-0001" and oi[0]["summary"] == "CVE-2099-0001 lets someone in")
seen_q.clear()
adv.osv_ubuntu_issues("openssh", "jammy", "1:8.9p1-3ubuntu0.10+esm2", osv_get)
check("osv: a package from Ubuntu Pro is asked about in Pro's records", seen_q[0]["package"]["ecosystem"] == P)

print(f"\n{sum(results)} of {len(results)} passed")
sys.exit(0 if all(results) else 1)
