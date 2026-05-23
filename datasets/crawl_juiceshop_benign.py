"""Generate benign OWASP Juice Shop traffic through the LatentGuard proxy.

Why this exists:
  The autoencoder + HDBSCAN trained on CSIC 2010 alone treats every
  non-/tienda1/ URL shape as out-of-distribution and blocks it. When the
  proxy is fronting Juice Shop instead of DVWA, that means /, /api/Products,
  /rest/products/search, /rest/captcha/, etc. all look anomalous. We bootstrap
  a benign baseline by crawling the actual upstream the proxy is protecting,
  weighted toward the shapes a real user would generate, and feed the audit
  rows back into training via --augment-mongo on the trainers.

What it does:
  1. Anonymous browsing of public Juice Shop endpoints (homepage, product
     listings, search with various terms, captcha, FTP listing, etc.).
  2. Registers a small pool of synthetic users via POST /api/Users/.
  3. Logs in via POST /rest/user/login, collects JWTs.
  4. Authenticated traffic: /rest/user/whoami, /api/BasketItems/<id>,
     /api/Quantitys, feedback POSTs.
  5. Loops to produce ~target total requests.

Filtering downstream:
  Every request carries User-Agent 'LatentGuard-Crawler/1.0'. The Mongo loader
  picks rows out by that UA and treats them as ground-truth benign, regardless
  of whether the (still-training) model decided to block them.

Run:
  python datasets/crawl_juiceshop_benign.py --proxy http://localhost:8080 --target 3000
"""
from __future__ import annotations

import argparse
import http.client
import json
import random
import string
import sys
import time
from urllib.parse import urlencode, urlparse

CRAWLER_UA = "LatentGuard-Crawler/1.0"

# Weighted public-GET path pool. Short paths ('/', '/api/Products') get heavy
# weight on purpose: they're the under-represented shapes vs CSIC's long
# /tienda1/index.jsp?... template, so the AE used to over-fire on them. Boosting
# their training share stops them from looking like outliers.
UNAUTH_GETS_WEIGHTED = [
    ("/",                                       14),
    ("/api/Products",                           10),
    ("/api/Quantitys",                           4),
    ("/api/Challenges/",                         4),
    ("/api/SecurityQuestions/",                  3),
    ("/api/Feedbacks/",                          3),
    ("/rest/captcha/",                           5),
    ("/rest/admin/application-version",          2),
    ("/rest/user/whoami",                        4),
    ("/rest/admin/application-configuration",    2),
    ("/rest/languages",                          2),
    ("/assets/i18n/en.json",                     2),
    ("/assets/public/images/JuiceShop_Logo.png", 2),
    ("/favicon.ico",                             3),
    ("/robots.txt",                              2),
    ("/sitemap.xml",                             1),
    ("/ftp/",                                    1),
    ("/main.js",                                 1),
    ("/styles.css",                              1),
    ("/runtime.js",                              1),
    ("/polyfills.js",                            1),
]
UNAUTH_GETS = [p for p, w in UNAUTH_GETS_WEIGHTED for _ in range(w)]

# Product IDs to fetch detail for. Juice Shop ships ~38 products by default.
PRODUCT_IDS = list(range(1, 39))

# Benign search terms — common product words. No SQLi, no XSS, no quotes.
SEARCH_TERMS = [
    "apple", "juice", "lemon", "orange", "banana", "raspberry", "strawberry",
    "melon", "fanta", "eggfruit", "carrot", "pineapple", "green", "organic",
    "bottle", "1000ml", "sugar", "free", "deluxe", "fresh", "ice", "tea",
    "smoothie", "berry", "fruit", "kiwi", "mango", "peach", "plum", "tropical",
]

# A pool of synthetic users we'll register + log in as. Email pattern uses
# the .test TLD (RFC 6761 reserved, never resolves in DNS) so we don't
# accidentally hit real mailboxes.
USER_POOL_SIZE = 8
USER_PREFIX = "lguser"
USER_DOMAIN = "lg-bench.test"
USER_PASSWORD = "BenignCrawl!2026"

# Throwaway-user registrations done DURING phase 4 to give the AE enough
# samples of the JSON register-body shape. With only USER_POOL_SIZE=8 register
# POSTs, the model never fits /api/Users/ and a fresh signup post-train is
# treated as anomalous. This pool seeds ~100 extra register samples.
THROWAWAY_REGISTER_COUNT = 100
THROWAWAY_PREFIX = "lgone"

REALISTIC_HEADER_SETS = [
    {  # Chrome on Windows
        "User-Agent": CRAWLER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    {  # Firefox
        "User-Agent": CRAWLER_UA,
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    },
    {  # XHR / fetch from SPA
        "User-Agent": CRAWLER_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    },
]


def _conn(proxy_url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urlparse(proxy_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    # Windows-specific gotcha: 'localhost' triggers AAAA->A fallback that adds
    # ~10s/req. Force IPv4 literal but keep the Host header readable.
    host_header = f"{host}:{port}"
    if host == "localhost":
        host = "127.0.0.1"
    return http.client.HTTPConnection(host, port, timeout=10), host_header


def _send(proxy_url: str, method: str, path: str, body: bytes | None,
          headers: dict[str, str], auth_token: str | None = None,
          ) -> tuple[int, str, dict[str, str]]:
    conn, host_hdr = _conn(proxy_url)
    h = dict(headers)
    h["Host"] = host_hdr
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    if body is not None:
        h.setdefault("Content-Type", "application/json")
        h["Content-Length"] = str(len(body))
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, text, resp_headers
    finally:
        conn.close()


def _json_body(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode()


def register_user(proxy_url: str, email: str, password: str) -> bool:
    """POST /api/Users/ to register. Returns True on 201 or 400 (already exists)."""
    headers = dict(REALISTIC_HEADER_SETS[2])  # XHR-like
    payload = _json_body({
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
        "securityAnswer": "Smith",
    })
    try:
        status, _, _ = _send(proxy_url, "POST", "/api/Users/", payload, headers)
        return status in (200, 201, 400, 409)  # 400/409 = already exists -> fine
    except Exception:
        return False


def login_user(proxy_url: str, email: str, password: str) -> str | None:
    """POST /rest/user/login. Returns JWT on success, None on failure."""
    headers = dict(REALISTIC_HEADER_SETS[2])
    payload = _json_body({"email": email, "password": password})
    try:
        status, body, _ = _send(proxy_url, "POST", "/rest/user/login", payload, headers)
        if status != 200:
            return None
        data = json.loads(body)
        return data.get("authentication", {}).get("token")
    except Exception:
        return None


def post_feedback(proxy_url: str, token: str | None) -> bool:
    """POST /api/Feedbacks/ — benign rating + comment."""
    headers = dict(REALISTIC_HEADER_SETS[2])
    # Juice Shop captcha solver: GET /rest/captcha/ returns {captchaId, captcha, answer}
    try:
        _, capt_body, _ = _send(proxy_url, "GET", "/rest/captcha/", None, headers, token)
        capt = json.loads(capt_body)
    except Exception:
        return False
    comments = [
        "Great juice, very refreshing",
        "Delivery was quick and packaging fine",
        "Will order again",
        "Tastes exactly as described",
        "Good value for money",
        "Solid product, recommended",
    ]
    payload = _json_body({
        "comment": random.choice(comments),
        "rating": random.randint(3, 5),
        "captchaId": capt.get("captchaId", 0),
        "captcha": str(capt.get("answer", "")),
    })
    try:
        status, _, _ = _send(proxy_url, "POST", "/api/Feedbacks/", payload, headers, token)
        return status in (200, 201)
    except Exception:
        return False


def basket_browse(proxy_url: str, token: str, bid: int) -> None:
    """Fetch basket then add a random product. Realistic shopping flow."""
    headers = dict(REALISTIC_HEADER_SETS[2])
    try:
        _send(proxy_url, "GET", f"/api/Baskets/{bid}", None, headers, token)
    except Exception:
        pass
    payload = _json_body({"ProductId": random.choice(PRODUCT_IDS),
                          "BasketId": str(bid), "quantity": random.randint(1, 3)})
    try:
        _send(proxy_url, "POST", "/api/BasketItems/", payload, headers, token)
    except Exception:
        pass


def crawl(proxy_url: str, target: int, sleep_ms: int) -> dict:
    counts = {"sent": 0, "ok": 0, "blocked": 0, "errors": 0}

    # ---------- Phase 1: anonymous browsing (~40% of budget) ----------
    unauth_budget = max(target * 4 // 10, 1)
    for _ in range(unauth_budget):
        headers = random.choice(REALISTIC_HEADER_SETS)
        # 70% pure path GET, 20% search query, 10% product detail.
        roll = random.random()
        if roll < 0.7:
            path = random.choice(UNAUTH_GETS)
        elif roll < 0.9:
            path = f"/rest/products/search?q={random.choice(SEARCH_TERMS)}"
        else:
            path = f"/api/Products/{random.choice(PRODUCT_IDS)}"
        try:
            status, _, _ = _send(proxy_url, "GET", path, None, headers, None)
            counts["sent"] += 1
            if status == 403:
                counts["blocked"] += 1
            elif 200 <= status < 400 or status == 401:
                counts["ok"] += 1
        except Exception as exc:
            counts["sent"] += 1
            counts["errors"] += 1
            if counts["errors"] < 5:
                print(f"  send error: {exc}", file=sys.stderr)
        time.sleep(sleep_ms / 1000.0)

    # ---------- Phase 2: register the synthetic user pool ----------
    print(f"  unauth phase done ({counts['sent']} sent); registering users...")
    users = [f"{USER_PREFIX}{i:02d}@{USER_DOMAIN}" for i in range(1, USER_POOL_SIZE + 1)]
    for email in users:
        if register_user(proxy_url, email, USER_PASSWORD):
            counts["sent"] += 1
            counts["ok"] += 1

    # ---------- Phase 3: log everyone in, collect JWTs + basket IDs ----------
    tokens: list[tuple[str, int]] = []  # (jwt, basket_id)
    for email in users:
        tok = login_user(proxy_url, email, USER_PASSWORD)
        counts["sent"] += 1
        if tok:
            counts["ok"] += 1
            # decode bid from JWT-adjacent /rest/user/whoami
            headers = dict(REALISTIC_HEADER_SETS[2])
            try:
                _, body, _ = _send(proxy_url, "GET", "/rest/user/whoami", None, headers, tok)
                data = json.loads(body)
                bid = data.get("user", {}).get("bid") or random.randint(1, USER_POOL_SIZE)
            except Exception:
                bid = random.randint(1, USER_POOL_SIZE)
            tokens.append((tok, int(bid)))
            counts["sent"] += 1
            counts["ok"] += 1
    if not tokens:
        print("  warn: no users logged in -- skipping auth phase", file=sys.stderr)
        return counts
    print(f"  got {len(tokens)} JWTs; entering auth phase")

    # ---------- Phase 4: authenticated browsing (~60% of remaining budget) ----------
    auth_budget = target - counts["sent"]
    # Schedule throwaway register POSTs evenly across phase 4 so the AE learns
    # the JSON register-body shape from many samples, not just the 8 pool users.
    register_every = max(auth_budget // max(THROWAWAY_REGISTER_COUNT, 1), 1)
    throwaway_idx = 0
    for i in range(max(auth_budget, 0)):
        headers = random.choice(REALISTIC_HEADER_SETS)
        tok, bid = random.choice(tokens)
        # Periodically register a throwaway user (no follow-up login) — purely
        # to seed register-body samples in the audit log.
        if i % register_every == 0 and throwaway_idx < THROWAWAY_REGISTER_COUNT:
            throwaway_email = f"{THROWAWAY_PREFIX}{throwaway_idx:03d}_{int(time.time()*1000)%100000}@{USER_DOMAIN}"
            register_user(proxy_url, throwaway_email, USER_PASSWORD)
            counts["sent"] += 1
            counts["ok"] += 1
            throwaway_idx += 1
            continue
        roll = random.random()
        try:
            if roll < 0.5:
                # plain GET browsing through authenticated pages
                path = random.choice(UNAUTH_GETS + [
                    f"/api/Products/{random.choice(PRODUCT_IDS)}",
                    f"/rest/products/search?q={random.choice(SEARCH_TERMS)}",
                    f"/api/Quantitys/{random.choice(PRODUCT_IDS)}",
                ])
                status, _, _ = _send(proxy_url, "GET", path, None, headers, tok)
            elif roll < 0.75:
                # basket flow
                basket_browse(proxy_url, tok, bid)
                counts["sent"] += 1  # basket_browse does 2 internally; count one more
                status = 200
            elif roll < 0.9:
                # feedback POST
                post_feedback(proxy_url, tok)
                counts["sent"] += 1  # feedback does 2 internally (captcha + feedback)
                status = 200
            else:
                # whoami refresh
                status, _, _ = _send(proxy_url, "GET", "/rest/user/whoami", None, headers, tok)
            counts["sent"] += 1
            if status == 403:
                counts["blocked"] += 1
            elif 200 <= status < 400 or status == 401:
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
    p.add_argument("--target", type=int, default=3000, help="total requests to send")
    p.add_argument("--sleep-ms", type=int, default=15)
    args = p.parse_args()

    print(f"Juice Shop benign crawl -> {args.proxy}, target={args.target} requests, UA={CRAWLER_UA}")
    print("Note: requests blocked by ML are still captured (audit log records features pre-decision).")
    t0 = time.perf_counter()
    res = crawl(args.proxy, args.target, args.sleep_ms)
    elapsed = time.perf_counter() - t0
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  sent={res['sent']}  ok2xx/3xx={res['ok']}  blocked403={res['blocked']}  errors={res['errors']}")
    print("Filter audit log by header['user-agent']=='LatentGuard-Crawler/1.0' to extract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
