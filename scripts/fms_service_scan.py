#!/usr/bin/env python3
"""FMS service scan: what each open port says about itself, read from outside with no sign-in.

Loaded by fms_exposure_check.py for every port it found OPEN. Each read is one connection that does what any
client does before signing in: reads the greeting a service sends (SSH, FTP, mail, MySQL, VNC), asks for the
web server's headers, or, for Windows Remote Desktop and file sharing, starts the NTLM handshake and stops
after the server's first answer, which carries its Windows version. Nothing signs in, nothing is guessed and
no exploit is sent.

From what the services say, it works out the product and version of each one and, where a service gives it
away, the operating system: an Ubuntu or Debian package revision in the SSH greeting, the Windows build from
the NTLM answer, Apple's Screen Sharing from its VNC greeting, an "(Ubuntu)" tag in a web server header.

What it can't see, and nobody can from outside: the operating system's patch level, kernel bugs and bugs that
need a sign-in first. Those are reported as not visible, never guessed.

Run on its own for one port:
    python3 fms_service_scan.py <hostname> <port>

Uses only the Python standard library, and runs under macOS's own Python (LibreSSL).
"""
import json
import re
import socket
import ssl
import struct
import sys

TIMEOUT = 4        # seconds per connection, as in the exposure check
READ_WAIT = 2.5    # seconds to wait for a greeting; a service that says nothing first is reported as not identified
MAX_READ = 4096    # bytes; a greeting or a header block is far smaller

# Ports where a web server is expected, and whether to try HTTPS first
WEB_TLS = {443, 2083, 2087, 5001, 6443, 8006, 8443, 9090, 9443, 10000, 10250, 16000}
WEB_PLAIN = {80, 5000, 7000, 8000, 8080, 8888, 9000, 5601, 15672, 9100, 9200, 2375}
TLS_FIRST = {465: "smtp", 993: "imap", 995: "pop3"}   # implicit TLS, then the same greeting as the plain port
GREETING = {21: "ftp", 22: "ssh", 25: "smtp", 587: "smtp", 110: "pop3", 143: "imap", 3306: "mysql",
            5900: "rfb", 5901: "rfb", 5902: "rfb"}
# FileMaker's own ports speak FileMaker's protocol; their meaning comes from the port list
FILEMAKER = {5003: "FileMaker Server (FileMaker Pro and Go clients)", 2399: "FileMaker Server ODBC/JDBC",
             16001: "FileMaker Server Admin Console", 16002: "FileMaker Server admin server",
             16003: "FileMaker Server Web Publishing Engine", 16004: "FileMaker Server database server",
             1895: "FileMaker Server database server", 5013: "FileMaker Server database server",
             8091: "FileMaker Server WebSocket tunnelling", 50003: "FileMaker Server service",
             50004: "FileMaker Script Engine", 3000: "FileMaker Server Web Publishing Engine",
             8998: "FileMaker Server Web Publishing Engine", 9889: "FileMaker Server Web Publishing Engine",
             9898: "FileMaker Server Web Publishing Engine", 16020: "FileMaker Server Web Publishing Engine",
             16021: "FileMaker Server Web Publishing Engine"}

# Ubuntu LTS releases by the OpenSSH version they ship, and Debian releases by their package suffix. Only these
# are named; anything else is reported as Ubuntu or Debian with the release not identified.
UBUNTU_BY_OPENSSH = {"7.6p1": ("18.04", "bionic"), "8.2p1": ("20.04", "focal"), "8.9p1": ("22.04", "jammy"),
                     "9.6p1": ("24.04", "noble")}
UBUNTU_CODENAME = {"18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble"}
DEBIAN_BY_SUFFIX = {"deb10": "10", "deb11": "11", "deb12": "12", "deb13": "13"}


def service(port, product="", version="", **extra):
    """One service as the scan reports it. cpe and matchable decide whether its version is looked up."""
    s = {"port": port, "product": product, "version": version, "os": "", "os_release": "", "os_evidence": "",
         "cpe": "", "matchable": False, "note": "", "said": ""}
    s.update(extra)
    return s


def clean(text, limit=160):
    """A greeting made printable and short, for the report."""
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text.replace("\r", " ").replace("\n", " ")).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def cpe(vendor, product, version):
    """An NVD CPE match string for the upstream version, without any update suffix (NVD matches 8.9, not 8.9:p1)."""
    base = re.match(r"\d+(?:\.\d+)*", version or "")
    return f"cpe:2.3:a:{vendor}:{product}:{base.group(0)}" if base else ""


def os_tag(text):
    """The operating system a header or greeting names in brackets or after a dash: Ubuntu, Debian, and so on."""
    for name in ("Ubuntu", "Debian", "Raspbian", "CentOS", "Red Hat", "Fedora", "FreeBSD", "Win64", "Win32", "Unix"):
        if re.search(rf"\b{name}\b", text or "", re.I):
            return {"Win64": "Windows", "Win32": "Windows", "Unix": ""}.get(name, name)
    return ""


# ---- Parsers: text in, service out. Pure, so the tests can feed them recorded greetings ----

def parse_ssh(port, banner):
    s = service(port, "SSH server", said=clean(banner))
    m = re.match(r"SSH-[\d.]+-(\S+)(?:\s+(.*))?", banner.strip())
    if not m:
        return s
    soft, comment = m.group(1), (m.group(2) or "").strip()
    w = re.match(r"OpenSSH_for_Windows_([\d.]+(?:p\d+)?)", soft)
    o = re.match(r"OpenSSH_([\d.]+(?:p\d+)?)", soft)
    d = re.match(r"dropbear_([\d.]+)", soft, re.I)
    if w:
        s.update(product="OpenSSH for Windows", version=w.group(1), os="Windows",
                 os_evidence="the SSH greeting says OpenSSH for Windows", cpe=cpe("openbsd", "openssh", w.group(1)),
                 matchable=True)
    elif o:
        v = o.group(1)
        s.update(product="OpenSSH", version=v, cpe=cpe("openbsd", "openssh", v), matchable=True)
        u = re.match(r"Ubuntu-(\S+)", comment)
        deb = re.match(r"Debian-(\S+)", comment)
        if u:
            rel = UBUNTU_BY_OPENSSH.get(v)
            s.update(os="Ubuntu", os_release=rel[0] if rel else "", package="openssh",
                     package_version=f"1:{v}-{u.group(1)}", codename=rel[1] if rel else "",
                     os_evidence=f"the SSH greeting names Ubuntu package {v}-{u.group(1)}")
            # Ubuntu patches without changing the upstream version: its own data decides, not NVD's version ranges
            s["matchable"] = False
            s["note"] = "Ubuntu package: checked against Ubuntu's security data" if rel else \
                "Ubuntu package on a release this scan doesn't name, so its fixes can't be checked"
        elif deb:
            suffix = re.search(r"\+(deb\d+)", deb.group(1))
            rel = DEBIAN_BY_SUFFIX.get(suffix.group(1)) if suffix else ""
            s.update(os="Debian", os_release=rel or "", package="openssh", package_version=f"1:{v}-{deb.group(1)}",
                     os_evidence=f"the SSH greeting names Debian package {v}-{deb.group(1)}",
                     note="Debian package: Debian fixes without changing the upstream version, so a match may "
                          "already be fixed; check the package version on security-tracker.debian.org")
        elif comment:
            tag = os_tag(comment)
            if tag:
                s.update(os=tag, os_evidence="the SSH greeting names " + tag)
    elif d:
        s.update(product="Dropbear SSH", version=d.group(1), cpe=cpe("dropbear_ssh_project", "dropbear_ssh", d.group(1)),
                 matchable=True)
    else:
        s.update(product=soft.split("_")[0] or "SSH server")
    return s


WEB_PRODUCTS = [  # header token, product, NVD vendor:product, whether the version means anything
    (r"nginx", "nginx", ("f5", "nginx"), True),
    (r"Apache", "Apache HTTP Server", ("apache", "http_server"), True),
    (r"Microsoft-IIS", "Microsoft IIS", ("microsoft", "internet_information_services"), False),
    (r"lighttpd", "lighttpd", ("lighttpd", "lighttpd"), True),
    (r"openresty", "OpenResty", ("openresty", "openresty"), True),
    (r"Caddy", "Caddy", ("caddyserver", "caddy"), True),
    (r"PHP", "PHP", ("php", "php"), True),
    (r"Jetty", "Eclipse Jetty", ("eclipse", "jetty"), True),
]


def parse_web(port, server_header, powered_by="", tls=False):
    """The web server, and anything X-Powered-By admits to, as one or two services."""
    out = []
    for text, kind in ((server_header, "server"), (powered_by, "powered")):
        if not text:
            continue
        # Apache lists modules after itself, separated by spaces: Apache/2.4.41 (Unix) OpenSSL/1.1.1 PHP/7.4.3
        for m in re.finditer(r"([A-Za-z][\w.\-]*)(?:/([\w.\-+~]+))?(?:\s*\(([^)]*)\))?", text):
            name, version, comment = m.group(1), m.group(2) or "", m.group(3) or ""
            known = next((p for p in WEB_PRODUCTS if re.fullmatch(p[0], name, re.I)), None)
            s = service(port, known[1] if known else name, version, said=clean(m.group(0)), web="https" if tls else "http")
            tag = os_tag(comment) or os_tag(version)
            if name.lower() == "microsoft-iis":
                s.update(os="Windows", os_evidence=f"the web server is Microsoft IIS {version}".strip(),
                         note="IIS 10.0 is the same on Windows Server 2016 to 2025, so the version says nothing about patches")
            elif name.lower().startswith("microsoft-"):
                s.update(os="Windows", os_evidence=f"the web server header names {name}")
            elif name.lower() == "airtunes":
                s.update(product="AirPlay Receiver (AirTunes)", os="macOS",
                         os_evidence="AirPlay Receiver answers, which macOS turns on by default",
                         note="turn off AirPlay Receiver on a server (System Settings, General, AirDrop & Handoff)")
            elif tag:
                s.update(os=tag, os_evidence=f"the {'web server' if kind == 'server' else 'X-Powered-By'} header names {tag}")
            ubuntu_rev = re.search(r"-\d*ubuntu[\d.]+", version)
            if known and version and known[3]:
                s["cpe"] = cpe(known[2][0], known[2][1], version)
                # A distribution build patches without changing the version, so NVD's ranges would be wrong
                packaged = bool(tag in ("Ubuntu", "Debian", "Red Hat", "CentOS") or ubuntu_rev or "deb" in version)
                s["matchable"] = not packaged
                if packaged:
                    s["note"] = (f"{tag or 'Distribution'} package: patched without the version changing, so the "
                                 "version can't show whether it's up to date")
            elif known and not version:
                s["note"] = "no version shown"
            out.append(s)
    return out


def parse_ftp(port, banner):
    s = service(port, "FTP server", said=clean(banner))
    for pat, prod, vendor in ((r"vsFTPd ([\d.]+)", "vsftpd", ("vsftpd_project", "vsftpd")),
                              (r"ProFTPD ([\d.]+\w*)", "ProFTPD", ("proftpd", "proftpd")),
                              (r"Pure-FTPd", "Pure-FTPd", None),
                              (r"FileZilla Server ([\d.]+)", "FileZilla Server", ("filezilla-project", "filezilla_server"))):
        m = re.search(pat, banner, re.I)
        if m:
            v = m.group(1) if m.groups() else ""
            s.update(product=prod, version=v, cpe=cpe(*vendor, v) if vendor and v else "", matchable=bool(vendor and v))
            break
    if re.search(r"Microsoft FTP Service", banner, re.I):
        s.update(product="Microsoft IIS FTP", os="Windows", os_evidence="the FTP greeting says Microsoft FTP Service")
    tag = os_tag(banner)
    if tag and not s["os"]:
        s.update(os=tag, os_evidence="the FTP greeting names " + tag)
    return s


def parse_mail(port, banner, kind):
    s = service(port, {"smtp": "Mail server (SMTP)", "pop3": "Mail server (POP3)", "imap": "Mail server (IMAP)"}[kind],
                said=clean(banner))
    for pat, prod, vendor in ((r"Postfix", "Postfix", None), (r"Exim ([\d.]+)", "Exim", ("exim", "exim")),
                              (r"Sendmail ([\d.]+)", "Sendmail", ("sendmail", "sendmail")),
                              (r"Dovecot", "Dovecot", None), (r"Courier", "Courier", None),
                              (r"Microsoft ESMTP|Microsoft Exchange", "Microsoft Exchange", None)):
        m = re.search(pat, banner, re.I)
        if m:
            v = m.group(1) if m.groups() else ""
            s.update(product=prod, version=v, cpe=cpe(*vendor, v) if vendor and v else "", matchable=bool(vendor and v))
            if prod == "Microsoft Exchange":
                s.update(os="Windows", os_evidence="the mail greeting names Microsoft")
            break
    tag = os_tag(banner)
    if tag and not s["os"]:
        s.update(os=tag, os_evidence="the mail greeting names " + tag)
    return s


def parse_mysql(port, data):
    """The MySQL or MariaDB greeting: protocol 10, then the version as text. An error packet means it refused us."""
    s = service(port, "MySQL or MariaDB")
    if len(data) < 6:
        return s
    if data[4] == 0xFF:
        s["note"] = "answers, but refuses connections from this address"
        s["said"] = clean(data[7:].decode("utf-8", "replace"))
        return s
    if data[4] != 0x0A:
        return s
    raw = data[5:data.index(b"\x00", 5)].decode("ascii", "replace") if b"\x00" in data[5:] else ""
    s["said"] = raw
    maria = re.search(r"(?:5\.5\.5-)?([\d.]+)-MariaDB", raw)
    v = maria.group(1) if maria else (re.match(r"[\d.]+", raw) or [""])[0]
    if maria:
        s.update(product="MariaDB", version=v, cpe=cpe("mariadb", "mariadb", v), matchable=True)
    else:
        s.update(product="MySQL", version=v, cpe=cpe("oracle", "mysql", v), matchable=True)
    u = re.search(r"ubuntu[\d.]*?(\d\d\.\d\d)", raw)
    if u:
        s.update(os="Ubuntu", os_release=u.group(1), os_evidence=f"the MySQL greeting names Ubuntu {u.group(1)}",
                 matchable=False, note="Ubuntu package: patched without the version changing")
    elif "deb" in raw or "Debian" in raw:
        deb = re.search(r"deb(\d+)", raw)
        s.update(os="Debian", os_release=deb.group(1) if deb else "", os_evidence="the MySQL greeting names a Debian package",
                 matchable=False, note="Debian package: patched without the version changing")
    return s


# VNC security types: 1 is no password at all; 30, 33, 35 and 36 are Apple's own
APPLE_RFB = {30, 33, 35, 36}


def parse_rfb(port, version_line, types):
    s = service(port, "VNC server", said=clean(version_line))
    m = re.match(r"RFB (\d{3})\.(\d{3})", version_line)
    if m:
        s["version"] = f"RFB {int(m.group(1))}.{int(m.group(2))}"
    if version_line.startswith("RFB 003.889") or APPLE_RFB & set(types):
        s.update(product="macOS Screen Sharing", os="macOS", os_evidence="the VNC greeting is Apple's Screen Sharing")
    if 1 in types:
        s["note"] = "ASKS FOR NO PASSWORD: anyone who connects gets the screen"
        s["no_auth"] = True
    return s


# ---- NTLM: the answer to an NTLM NEGOTIATE carries the server's Windows version and names ----

NTLM_FLAGS = 0xE2888207   # Unicode, OEM, request target, NTLM, always sign, extended session security, target info,
                          # version, 128-bit, key exchange, 56-bit: what a Windows client offers, asking for the version


def ntlm_negotiate():
    return b"NTLMSSP\x00" + struct.pack("<II", 1, NTLM_FLAGS) + b"\x00" * 16 + b"\x0a\x00\x63\x45\x00\x00\x00\x0f"


def parse_ntlm_challenge(blob):
    """The Windows version and the names an NTLM CHALLENGE gives away, or None if there isn't one in blob."""
    i = blob.find(b"NTLMSSP\x00\x02\x00\x00\x00")
    if i < 0:
        return None
    c = blob[i:]
    if len(c) < 56:
        return None
    flags = struct.unpack_from("<I", c, 20)[0]
    info_len, _, info_off = struct.unpack_from("<HHI", c, 40)
    out = {"names": {}}
    if flags & 0x02000000:
        major, minor, build = c[48], c[49], struct.unpack_from("<H", c, 50)[0]
        out.update(major=major, minor=minor, build=build)
    keys = {1: "netbios_computer", 2: "netbios_domain", 3: "dns_computer", 4: "dns_domain", 5: "dns_forest"}
    pos, end = info_off, min(info_off + info_len, len(c))
    while pos + 4 <= end:
        av, ln = struct.unpack_from("<HH", c, pos)
        if av == 0:
            break
        if av in keys:
            out["names"][keys[av]] = c[pos + 4:pos + 4 + ln].decode("utf-16-le", "replace")
        pos += 4 + ln
    return out


def windows_service(port, product, ntlm, lifecycle=None):
    s = service(port, product)
    if not ntlm:
        return s
    names = ntlm.get("names") or {}
    if ntlm.get("build") == 0 or (ntlm.get("major"), ntlm.get("minor"), ntlm.get("build")) == (6, 1, 7600):
        # Samba (Linux, NAS boxes) and macOS's own file sharing answer NTLM with a placeholder: no version, or
        # Windows 7 before Service Pack 1, which no supported Windows machine still reports
        s["note"] = "answers NTLM with a placeholder version, as macOS file sharing and Samba do"
        if names.get("dns_domain", "").lower() == "local":
            s.update(os="macOS", os_evidence="file sharing names the .local domain, as macOS does",
                     os_weak=True)
    elif "build" in ntlm:
        ver = f"{ntlm['major']}.{ntlm['minor']}.{ntlm['build']}"
        name = windows_name(ver, lifecycle)
        s.update(version=ver, os="Windows", os_release=name or f"build {ver}",
                 os_evidence=f"{product} reports Windows {ver} in its NTLM answer")
    names = ntlm.get("names") or {}
    if names:
        shown = [names[k] for k in ("netbios_computer", "dns_domain") if names.get(k)]
        if shown:
            s["note"] = (s["note"] + "; " if s["note"] else "") + \
                "gives away its computer and domain name before sign-in: " + ", ".join(shown)
        s["names"] = names
    return s


def windows_name(version, lifecycle=None):
    """The Windows release for an NTLM version such as 10.0.20348, from os-lifecycle.json's build ranges."""
    m = re.fullmatch(r"(\d+\.\d+)\.(\d+)", version or "")
    if not m:
        return ""
    for b in (lifecycle or {}).get("windows", []):
        if b["version"] == m.group(1) and b["builds"][0] <= int(m.group(2)) <= b["builds"][1]:
            return b["name"]
    return ""


def der(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + struct.pack(">H", n)
    return bytes([tag]) + length + content


def credssp_negotiate():
    """A CredSSP TSRequest, version 3, carrying an NTLM NEGOTIATE: what an RDP client sends first under NLA."""
    version = der(0xA0, der(0x02, b"\x03"))
    token = der(0xA1, der(0x30, der(0x30, der(0xA0, der(0x04, ntlm_negotiate())))))
    return der(0x30, version + token)


def unverified_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return ctx


def recv_some(sock, wait=READ_WAIT, until=None):
    sock.settimeout(wait)
    data = b""
    try:
        while len(data) < MAX_READ:
            chunk = sock.recv(MAX_READ - len(data))
            if not chunk:
                break
            data += chunk
            if until and until(data):
                break
    except (socket.timeout, OSError, ssl.SSLError):
        pass
    return data


def rdp(host, port=3389, lifecycle=None):
    """Remote Desktop: ask for TLS and Network Level Authentication, then read the Windows version from NTLM."""
    neg = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        raw.sendall(neg)
        reply = recv_some(raw, until=lambda d: len(d) >= 19)
        if len(reply) < 11 or reply[0] != 3:
            return service(port, "Remote Desktop", note="answered, but not as Remote Desktop")
        if len(reply) >= 19 and reply[11] == 0x03:   # RDP_NEG_FAILURE: the server can't do TLS or NLA
            return service(port, "Windows Remote Desktop",
                           note="USES OLD RDP SECURITY: no TLS and no Network Level Authentication")
        selected = struct.unpack_from("<I", reply, 15)[0] if len(reply) >= 19 and reply[11] == 0x02 else 0
        if not selected & 0x02:
            s = service(port, "Windows Remote Desktop", os="Windows", os_evidence="Remote Desktop answers")
            s["note"] = ("NETWORK LEVEL AUTHENTICATION IS OFF: the sign-in screen is shown to anyone before they "
                         "authenticate") if selected & 0x01 else "USES OLD RDP SECURITY: no TLS"
            s["nla"] = False
            return s
        with unverified_tls().wrap_socket(raw, server_hostname=host) as t:
            t.sendall(credssp_negotiate())
            answer = recv_some(t, until=lambda d: b"NTLMSSP\x00\x02" in d and len(d) > 120)
    s = windows_service(port, "Windows Remote Desktop", parse_ntlm_challenge(answer), lifecycle)
    s["nla"] = True
    return s


def smb2_header(command, message_id):
    return (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, command, 31, 0, 0, message_id, 0, 0, 0) + b"\x00" * 16)


def netbios(payload):
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def smb(host, port=445, lifecycle=None):
    """SMB: negotiate SMB 2 or 3, then start a session with an NTLM NEGOTIATE and read the server's answer."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + b"\x11" * 16 + b"\x00" * 8 + \
        b"".join(struct.pack("<H", d) for d in dialects)
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.sendall(netbios(smb2_header(0, 0) + body))
        reply = recv_some(sock, until=lambda d: len(d) >= 4 and len(d) >= 4 + int.from_bytes(d[1:4], "big"))
        if len(reply) < 4 + 64 + 6 or reply[4:8] != b"\xfeSMB":
            if reply[4:8] == b"\xffSMB":
                return service(port, "SMB file sharing", version="SMB1 only", note="ONLY SPEAKS SMB1, which is long retired")
            return service(port, "SMB file sharing", note="answered, but didn't agree an SMB 2 or 3 dialect with this scan")
        status = struct.unpack_from("<I", reply, 4 + 8)[0]
        dialect = struct.unpack_from("<H", reply, 4 + 64 + 4)[0] if status == 0 else 0
        token = ntlm_negotiate()
        setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(token), 0) + token
        sock.sendall(netbios(smb2_header(1, 1) + setup))
        answer = recv_some(sock, until=lambda d: b"NTLMSSP\x00\x02" in d and len(d) > 150)
    s = windows_service(port, "SMB file sharing", parse_ntlm_challenge(answer), lifecycle)
    if not s["note"] and not s["version"]:
        s["note"] = "doesn't give its version"
    if dialect:
        s["dialect"] = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2"}.get(dialect, hex(dialect))
    return s


# ---- Network readers ----

def greeting(host, port, tls=False, wait=READ_WAIT):
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        if tls:
            with unverified_tls().wrap_socket(raw, server_hostname=host) as t:
                return recv_some(t, wait, until=lambda d: b"\n" in d)
        return recv_some(raw, wait, until=lambda d: b"\n" in d)


def rfb(host, port):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        line = recv_some(sock, until=lambda d: len(d) >= 12)[:12].decode("ascii", "replace")
        if not line.startswith("RFB "):
            return line, []
        sock.sendall(b"RFB 003.008\n" if line >= "RFB 003.007" else b"RFB 003.003\n")
        data = recv_some(sock, until=lambda d: len(d) >= 1 and (d[0] == 0 or len(d) >= 1 + d[0]))
        if line >= "RFB 003.007":
            return line, list(data[1:1 + data[0]]) if data and data[0] else []
        return line, [struct.unpack(">I", data[:4])[0]] if len(data) >= 4 else []


def web_headers(host, port, tls):
    """Server and X-Powered-By from one GET /, with no credentials."""
    import http.client
    conn = (http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=unverified_tls()) if tls
            else http.client.HTTPConnection(host, port, timeout=TIMEOUT))
    try:
        conn.request("GET", "/", headers={"User-Agent": "fms-exposure-check"})
        r = conn.getresponse()
        r.read(2000)
        return r.status, r.getheader("Server", ""), r.getheader("X-Powered-By", "")
    finally:
        conn.close()


def identify(host, port, what="", lifecycle=None):
    """Read one open port and say what it is. Never raises: a failed read is reported as not identified."""
    try:
        if port in FILEMAKER:
            return service(port, FILEMAKER[port], note="FileMaker's own protocol: no version shown before sign-in")
        if port == 3389:
            return rdp(host, port, lifecycle)
        if port == 445:
            return smb(host, port, lifecycle)
        if port in GREETING or port in TLS_FIRST:
            kind = GREETING.get(port) or TLS_FIRST[port]
            if kind == "rfb":
                line, types = rfb(host, port)
                return parse_rfb(port, line, types) if line.startswith("RFB ") else service(port, what, said=clean(line))
            data = greeting(host, port, tls=port in TLS_FIRST)
            if kind == "mysql":
                return parse_mysql(port, data)
            text = data.decode("utf-8", "replace")
            if kind == "ssh" or text.startswith("SSH-"):
                return parse_ssh(port, text)
            if kind == "ftp":
                return parse_ftp(port, text)
            return parse_mail(port, text, kind)
        if port in WEB_TLS or port in WEB_PLAIN:
            for tls in ((True, False) if port in WEB_TLS else (False, True)):
                try:
                    status, server, powered = web_headers(host, port, tls)
                except (OSError, ssl.SSLError, ValueError):
                    continue
                found = parse_web(port, server, powered, tls)
                if found:
                    return found
                return service(port, what or "Web server", note=f"answers {'HTTPS' if tls else 'HTTP'} {status}, names no software",
                               web="https" if tls else "http")
            return service(port, what, note="open, but didn't answer as a web server")
        # Anything else: listen for a greeting, in case the service speaks first
        data = greeting(host, port)
        text = data.decode("utf-8", "replace")
        if text.startswith("SSH-"):
            return parse_ssh(port, text)
        return service(port, what, said=clean(text), note="open; says nothing this scan can read" if not text.strip() else "")
    except (OSError, ssl.SSLError, ValueError, struct.error, IndexError) as e:
        return service(port, what, note=f"open, but couldn't be read ({e.__class__.__name__})")


def best_os(services):
    """The operating system the services point to, strongest evidence first, with every piece of evidence."""
    rank = lambda s: (0 if s["os"] == "Windows" and s.get("os_release") else
                      1 if s.get("package_version") or s.get("os_release") else 3 if s.get("os_weak") else 2)
    named = sorted([s for s in services if s["os"]], key=rank)
    if not named:
        return {"name": "", "release": "", "evidence": [], "agree": True}
    top = named[0]
    names = {s["os"] for s in named}
    return {"name": top["os"], "release": top.get("os_release", ""), "evidence": [f"{s['port']}: {s['os_evidence']}" for s in named],
            "agree": len(names) == 1, "others": sorted(names - {top["os"]})}


def os_label(name, release):
    """Ubuntu 22.04, or Windows Server 2022 rather than Windows Windows Server 2022."""
    if not release:
        return name
    return release if release.startswith(name) else f"{name} {release}"


def describe(s):
    """One service as a line of the report, after the port."""
    label = " ".join(x for x in (s["product"], s["version"]) if x) or "not identified"
    bits = []
    if s["os"]:
        bits.append(os_label(s["os"], s.get("os_release", "")))
    if s.get("package_version"):
        bits.append("package " + s["package_version"])
    if s.get("dialect"):
        bits.append(s["dialect"])
    if s["note"]:
        bits.append(s["note"])
    return label + (f" ({'; '.join(bits)})" if bits else "")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    print(json.dumps(identify(sys.argv[1], int(sys.argv[2])), indent=1))
