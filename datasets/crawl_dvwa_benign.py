"""Generate benign DVWA traffic through the LatentGuard proxy.

Why this exists:
  CSIC 2010 is the only published large benign HTTP corpus we have, but it's
  narrow -- every path looks like /tienda1/index.jsp?... -- so an autoencoder
  trained on it alone treats *any* short / non-shop path (e.g. a browser hitting
  GET /, /favicon.ico, /robots.txt) as wildly out-of-distribution and the
  consensus engine blocks it. There is no public "DVWA normal traffic" dataset,
  so we generate one ourselves by crawling the actual upstream the proxy is
  protecting. The audit log captures features for every request regardless of
  block status, so this works even while the model is still mis-blocking.

What it does:
  1. Hits a curated set of unauthenticated DVWA endpoints (homepage, login
     page, static assets, /favicon.ico, /robots.txt) many times with realistic
     header sets.
  2. Logs into DVWA (admin/password by default), sets security level low.
  3. Hits authenticated vulnerability pages with *safe* parameter values
     (no SQLi, no XSS payloads -- the point is benign traffic).
  4. Loops to produce ~CRAWL_TARGET total requests.

Filtering downstream:
  Every request carries User-Agent: 'LatentGuard-Crawler/1.0'. The Mongo loader
  picks rows out by that UA and treats them as ground-truth benign, regardless
  of whether the current (broken) model decided to block them.

Run:
  python datasets/crawl_dvwa_benign.py --proxy http://localhost:8080 --target 2000
"""
from __future__ import annotations

import argparse
import random
import re
import sys
import time
from urllib.parse import urlencode

import http.client
from urllib.parse import urlparse

CRAWLER_UA = "LatentGuard-Crawler/1.0"

# Each (path, weight) — weight controls how often that path is sampled. Short
# paths ("/", "/login.php") get heavy weight on purpose: the autoencoder
# previously over-fired on them because they were under-represented vs CSIC's
# /tienda1/index.jsp?... (length ~40+) shape. Boosting their training share
# stops them from looking like outliers.
UNAUTH_GETS_WEIGHTED = [
    ("/",                              12),
    ("/login.php",                      8),
    ("/index.php",                      6),
    ("/favicon.ico",                    4),
    ("/robots.txt",                     4),
    ("/about.php",                      2),
    ("/instructions.php",               2),
    ("/setup.php",                      2),
    ("/dvwa/css/main.css",              2),
    ("/dvwa/css/login.css",             2),
    ("/dvwa/js/dvwaPage.js",            2),
    ("/dvwa/images/login_logo.png",     1),
    ("/dvwa/images/logo.png",           1),
    ("/dvwa/images/RandomStorm.png",    1),
]
UNAUTH_GETS = [p for p, w in UNAUTH_GETS_WEIGHTED for _ in range(w)]

# (path, query-string-template-with-{}-placeholders, value-list-per-placeholder).
# Keep values benign: numeric ids, normal usernames, short text fields.
AUTH_GET_TEMPLATES = [
    ("/vulnerabilities/sqli/", "id={}&Submit=Submit", [["1", "2", "3", "4", "5"]]),
    ("/vulnerabilities/sqli_blind/", "id={}&Submit=Submit", [["1", "2", "3"]]),
    ("/vulnerabilities/xss_r/", "name={}", [["alice", "bob", "carol", "dave", "eve"]]),
    ("/vulnerabilities/xss_s/", "", []),
    ("/vulnerabilities/exec/", "", []),
    ("/vulnerabilities/csrf/", "", []),
    ("/vulnerabilities/upload/", "", []),
    ("/vulnerabilities/captcha/", "", []),
    ("/vulnerabilities/fi/", "page={}", [["include.php", "file1.php", "file2.php", "file3.php"]]),
    ("/vulnerabilities/brute/",
     "username={}&password={}&Login=Login",
     [["admin", "user", "test"], ["password", "pass123", "letmein"]]),
    ("/security.php", "", []),
    ("/vulnerabilities/view_help.php", "id={}&security=low", [["sqli", "xss_r", "exec", "fi", "brute"]]),
    ("/vulnerabilities/view_source.php", "id={}&security=low", [["sqli", "xss_r", "exec", "fi", "brute"]]),
    ("/dvwa/includes/dvwaPhpIds.inc.php", "", []),  # 404 is fine, still benign-shaped
]

# (path, body-template, value-list-per-placeholder)
# NB: login.php POSTs are NOT in this list -- they need a fresh user_token
# harvested from a prior GET, which the static template can't do. The
# auth-loop calls do_login_post() periodically instead so the AE sees
# realistic login bodies (with real 32-char hex tokens that pump digit_ratio).
AUTH_POSTS = [
    ("/vulnerabilities/exec/", "ip={}&Submit=Submit", [["127.0.0.1", "8.8.8.8", "1.1.1.1", "localhost"]]),
    ("/vulnerabilities/xss_s/", "txtName={}&mtxMessage={}&btnSign=Sign+Guestbook",
     [["alice", "bob", "carol"], ["hello+world", "great+post", "thanks+for+sharing"]]),
    ("/vulnerabilities/csrf/",
     "password_new={}&password_conf={}&Change=Change",
     [["newpass1", "newpass2", "secret123"], ["newpass1", "newpass2", "secret123"]]),
]

LOGIN_USERS = ["admin", "dvwa", "user", "test", "guest", "gordonb", "1337", "pablo", "smithy"]
LOGIN_PASSES = ["password", "dvwa", "123456", "letmein", "changeme", "admin", "password123"]


def do_login_post(proxy_url: str) -> bool:
    """One realistic login flow: GET /login.php to harvest user_token, then
    POST credentials. Generates audit rows whose POST body shape matches what
    real browsers send (long hex token in the form-encoded body)."""
    headers = dict(REALISTIC_HEADER_SETS[0])
    try:
        status, body, resp_h = _send(proxy_url, "GET", "/login.php", None, headers, None)
    except Exception:
        return False
    cookie = None
    sc = resp_h.get("set-cookie", "")
    if "PHPSESSID=" in sc:
        cookie = sc.split(";", 1)[0]
    token = _extract_token(body)
    if not token:
        return False
    payload = urlencode({
        "username": random.choice(LOGIN_USERS),
        "password": random.choice(LOGIN_PASSES),
        "Login": "Login",
        "user_token": token,
    }).encode()
    try:
        _send(proxy_url, "POST", "/login.php", payload, headers, cookie)
        return True
    except Exception:
        return False

REALISTIC_HEADER_SETS = [
    {  # Edge on Windows
        "User-Agent": CRAWLER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    {  # Firefox-ish
        "User-Agent": CRAWLER_UA,
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    },
    {  # mobile-ish
        "User-Agent": CRAWLER_UA,
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "Connection": "keep-alive",
    },
]


def _conn(proxy_url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    return http.client.HTTPConnection(host, port, timeout=5), f"{host}:{port}"


def _send(proxy_url: str, method: str, path: str, body: bytes | None,
          headers: dict[str, str], cookie: str | None) -> tuple[int, str, dict[str, str]]:
    conn, host_hdr = _conn(proxy_url)
    h = dict(headers)
    h["Host"] = host_hdr
    if cookie:
        h["Cookie"] = cookie
    if body is not None:
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        h["Content-Length"] = str(len(body))
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, text, resp_headers
    finally:
        conn.close()


def _expand(template: str, value_lists: list[list[str]]) -> str:
    """Pick one random value per placeholder."""
    if not value_lists:
        return template
    picked = [random.choice(vs) for vs in value_lists]
    return template.format(*picked)


_TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", re.IGNORECASE)


def _extract_token(html: str) -> str | None:
    m = _TOKEN_RE.search(html)
    return m.group(1) if m else None


def login(proxy_url: str, username: str, password: str) -> str | None:
    """Returns the PHPSESSID cookie if login worked, else None."""
    headers = dict(REALISTIC_HEADER_SETS[0])
    # 1) GET /login.php to harvest user_token + initial cookie
    status, body, resp_h = _send(proxy_url, "GET", "/login.php", None, headers, None)
    set_cookie = resp_h.get("set-cookie", "")
    cookie = None
    if "PHPSESSID=" in set_cookie:
        cookie = set_cookie.split(";", 1)[0]
    token = _extract_token(body)
    if not token:
        return cookie  # DVWA may not require token on first run; still return cookie

    # 2) POST /login.php with credentials
    payload = urlencode({"username": username, "password": password,
                         "Login": "Login", "user_token": token})
    status, body, resp_h = _send(proxy_url, "POST", "/login.php",
                                  payload.encode(), headers, cookie)
    new_cookie = resp_h.get("set-cookie", "")
    if "PHPSESSID=" in new_cookie:
        cookie = new_cookie.split(";", 1)[0]
    # Login success in DVWA: 302 Location: index.php (status 302/200), and
    # subsequent /index.php contains "Logout" link.
    return cookie


def set_security(proxy_url: str, cookie: str, level: str = "low") -> None:
    headers = dict(REALISTIC_HEADER_SETS[0])
    status, body, _ = _send(proxy_url, "GET", "/security.php", None, headers, cookie)
    token = _extract_token(body)
    payload = urlencode({"security": level, "seclev_submit": "Submit",
                         "user_token": token or ""})
    _send(proxy_url, "POST", "/security.php", payload.encode(), headers, cookie)


def crawl(proxy_url: str, target: int, username: str, password: str, sleep_ms: int) -> dict:
    counts = {"sent": 0, "ok": 0, "blocked": 0, "errors": 0}

    # Phase 1: unauthenticated browsing (no cookie). ~30% of budget.
    unauth_budget = max(target // 3, 1)
    for _ in range(unauth_budget):
        path = random.choice(UNAUTH_GETS)
        headers = random.choice(REALISTIC_HEADER_SETS)
        try:
            status, _, _ = _send(proxy_url, "GET", path, None, headers, None)
            counts["sent"] += 1
            if status == 403:
                counts["blocked"] += 1
            elif 200 <= status < 400:
                counts["ok"] += 1
        except Exception as exc:
            counts["sent"] += 1
            counts["errors"] += 1
            if counts["errors"] < 5:
                print(f"  send error: {exc}", file=sys.stderr)
        time.sleep(sleep_ms / 1000.0)

    # Phase 2: login, then authenticated traffic
    print(f"  unauth phase done; logging in as {username} ...")
    cookie = login(proxy_url, username, password)
    if cookie:
        print(f"  got session cookie {cookie[:20]}...")
        try:
            set_security(proxy_url, cookie, "low")
        except Exception as exc:
            print(f"  warn: set_security failed: {exc}", file=sys.stderr)
    else:
        print("  warn: no session cookie -- continuing as anonymous", file=sys.stderr)

    auth_budget = target - counts["sent"]
    for i in range(auth_budget):
        headers = random.choice(REALISTIC_HEADER_SETS)
        # 1 in 8 iterations: do a real login flow (GET /login.php, harvest
        # user_token, POST credentials). Without these, the AE never sees the
        # 32-char hex token shape that real browser logins produce.
        if i % 8 == 0:
            if do_login_post(proxy_url):
                counts["sent"] += 2  # the GET + the POST
                counts["ok"] += 1
            time.sleep(sleep_ms / 1000.0)
            continue
        # 70/30 GET vs POST
        if random.random() < 0.7:
            path, qtmpl, vlists = random.choice(AUTH_GET_TEMPLATES)
            query = _expand(qtmpl, vlists) if qtmpl else ""
            full = f"{path}?{query}" if query else path
            method, body = "GET", None
        else:
            path, btmpl, vlists = random.choice(AUTH_POSTS)
            body_str = _expand(btmpl, vlists)
            method, body = "POST", body_str.encode()
            full = path
        try:
            status, _, _ = _send(proxy_url, method, full, body, headers, cookie)
            counts["sent"] += 1
            if status == 403:
                counts["blocked"] += 1
            elif 200 <= status < 400:
                counts["ok"] += 1
        except Exception as exc:
            counts["sent"] += 1
            counts["errors"] += 1
            if counts["errors"] < 5:
                print(f"  send error: {exc}", file=sys.stderr)
        time.sleep(sleep_ms / 1000.0)

    return counts


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--proxy", default="http://localhost:8080")
    p.add_argument("--target", type=int, default=2000, help="total requests to send")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="password")
    p.add_argument("--sleep-ms", type=int, default=20)
    args = p.parse_args()

    print(f"DVWA benign crawl -> {args.proxy}, target={args.target} requests, UA={CRAWLER_UA}")
    print("Note: requests blocked by ML are still captured (audit log records features pre-decision).")
    t0 = time.perf_counter()
    res = crawl(args.proxy, args.target, args.user, args.password, args.sleep_ms)
    elapsed = time.perf_counter() - t0
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  sent={res['sent']}  ok2xx/3xx={res['ok']}  blocked403={res['blocked']}  errors={res['errors']}")
    print("Filter audit log by header['user-agent']=='LatentGuard-Crawler/1.0' to extract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
