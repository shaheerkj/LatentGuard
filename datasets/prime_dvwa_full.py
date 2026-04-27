"""One-shot prime: full DVWA browser session many times over.

Why this exists:
  Each DVWA form (login, setup, security level, exec, csrf, xss_s) submits a
  unique field set together with a fresh 32-char hex `user_token`. Each is its
  own request shape the AE has never seen unless we send it through the proxy
  during training data collection. The base `crawl_dvwa_benign.py` covers
  paths but doesn't exhaustively touch every form, so real users clicking
  around DVWA hit OOD shapes one by one and trip the consensus engine.

  This script logs in, sets security level, then loops through GETs and
  real form-POSTs (token harvested per submission) so every audit row
  matches the body shape a real browser would produce.

Run:
  python datasets/prime_dvwa_full.py --proxy http://localhost:8080 --iters 80
Then retrain via `docker exec latentguard-ml python -m training.train_autoencoder --epochs 40 --augment-mongo`.
"""
from __future__ import annotations

import argparse
import http.client
import random
import re
import sys
import time
import urllib.parse

UA = "LatentGuard-Crawler/1.0"
TOK_RE = re.compile(r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]+)['"]""", re.I)


def _send(host: str, port: int, method: str, path: str,
          body: bytes | None = None, cookie: str | None = None) -> tuple[int, str, list[str]]:
    h = {"Host": f"{host}:{port}", "User-Agent": UA, "Accept": "text/html,*/*"}
    if cookie:
        h["Cookie"] = cookie
    if body:
        h["Content-Type"] = "application/x-www-form-urlencoded"
        h["Content-Length"] = str(len(body))
    c = http.client.HTTPConnection(host, port, timeout=5)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        text = r.read().decode("utf-8", errors="replace")
        # DVWA sets multiple Set-Cookie headers (security=, PHPSESSID=).
        # Return the list, not a dict-collapsed single value.
        cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        return r.status, text, cookies
    finally:
        c.close()


def _merge_cookies(existing: str | None, new_set_cookies: list[str]) -> str | None:
    """Merge Set-Cookie values into a Cookie header. Existing cookies persist
    unless the new headers overwrite the same name."""
    jar: dict[str, str] = {}
    if existing:
        for kv in existing.split(";"):
            if "=" in kv:
                k, _, v = kv.strip().partition("=")
                jar[k] = v
    for sc in new_set_cookies:
        first = sc.split(";", 1)[0]
        if "=" in first:
            k, _, v = first.partition("=")
            jar[k.strip()] = v.strip()
    if not jar:
        return None
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def login(host: str, port: int) -> str | None:
    st, body, set_cookies = _send(host, port, "GET", "/login.php")
    cookie = _merge_cookies(None, set_cookies)
    m = TOK_RE.search(body)
    if not m:
        return None
    payload = urllib.parse.urlencode({
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": m.group(1),
    }).encode()
    _, _, set_cookies2 = _send(host, port, "POST", "/login.php", body=payload, cookie=cookie)
    cookie = _merge_cookies(cookie, set_cookies2)
    return cookie


# Each entry: (form-page-path, post-path, body-builder(token) -> bytes)
def _setup_body(t: str) -> bytes:
    return urllib.parse.urlencode({
        "create_db": "Create / Reset Database", "user_token": t}).encode()

def _security_body(t: str) -> bytes:
    return urllib.parse.urlencode({
        "security": random.choice(["low", "medium", "high", "impossible"]),
        "seclev_submit": "Submit", "user_token": t}).encode()

def _exec_body(t: str) -> bytes:
    return urllib.parse.urlencode({
        "ip": random.choice(["127.0.0.1", "8.8.8.8", "1.1.1.1", "localhost", "example.com"]),
        "Submit": "Submit", "user_token": t}).encode()

def _csrf_body(t: str) -> bytes:
    p = random.choice(["pass1", "newpass", "letmein2", "secret123"])
    return urllib.parse.urlencode({
        "password_new": p, "password_conf": p, "Change": "Change",
        "user_token": t}).encode()

def _xss_s_body(t: str) -> bytes:
    return urllib.parse.urlencode({
        "txtName": random.choice(["alice", "bob", "carol", "dave"]),
        "mtxMessage": random.choice(["hello", "great post", "thanks!", "nice"]),
        "btnSign": "Sign Guestbook", "user_token": t}).encode()

POST_FLOWS = [
    ("/setup.php",                    _setup_body),
    ("/security.php",                 _security_body),
    ("/vulnerabilities/exec/",        _exec_body),
    ("/vulnerabilities/csrf/",        _csrf_body),
    ("/vulnerabilities/xss_s/",       _xss_s_body),
]

GET_PATHS = [
    "/", "/index.php", "/login.php", "/logout.php",
    "/about.php", "/instructions.php", "/setup.php", "/security.php",
    "/vulnerabilities/sqli/?id=1&Submit=Submit",
    "/vulnerabilities/sqli/?id=2&Submit=Submit",
    "/vulnerabilities/sqli/?id=alice&Submit=Submit",
    "/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    "/vulnerabilities/xss_r/?name=alice",
    "/vulnerabilities/xss_r/?name=bob",
    "/vulnerabilities/xss_r/?name=hello+world",
    "/vulnerabilities/fi/?page=include.php",
    "/vulnerabilities/fi/?page=file1.php",
    "/vulnerabilities/captcha/",
    "/vulnerabilities/upload/",
    "/vulnerabilities/brute/?username=admin&password=password&Login=Login",
    "/favicon.ico", "/robots.txt",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="http://localhost:8080")
    ap.add_argument("--iters", type=int, default=80,
                    help="iteration count; ~26 reqs per iter, so 80 -> ~2080")
    ap.add_argument("--sleep-ms", type=int, default=3)
    args = ap.parse_args()

    p = urllib.parse.urlparse(args.proxy)
    host = p.hostname or "localhost"
    port = p.port or 80

    print(f"[prime] login as admin/password ...")
    cookie = login(host, port)
    if not cookie:
        print("[prime] LOGIN FAILED -- check proxy/ML status", file=sys.stderr)
        return 1
    print(f"[prime] cookie={cookie[:24]}...")

    sent = 0
    for i in range(args.iters):
        for g in GET_PATHS:
            try:
                _send(host, port, "GET", g, cookie=cookie)
                sent += 1
            except Exception:
                pass
            time.sleep(args.sleep_ms / 1000.0)
        for form_path, builder in POST_FLOWS:
            try:
                _, body, _ = _send(host, port, "GET", form_path, cookie=cookie)
                m = TOK_RE.search(body)
                if not m:
                    continue
                _send(host, port, "POST", form_path,
                      body=builder(m.group(1)), cookie=cookie)
                sent += 2
            except Exception:
                pass
            time.sleep(args.sleep_ms / 1000.0)
        if i % 20 == 19:
            new_cookie = login(host, port)
            if new_cookie:
                cookie = new_cookie

    print(f"[prime] done: {sent} requests sent (UA={UA})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
