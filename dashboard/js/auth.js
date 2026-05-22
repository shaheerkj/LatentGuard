// Token storage + redirect glue. Loaded before app.js on the dashboard, and
// alone on login.html. Single-admin model for now -- when M10 RBAC ships
// this is where role-based UI gating goes.

const LG_AUTH = (function () {
    const TOKEN_KEY = "lg.jwt";
    const EXP_KEY = "lg.jwt.exp";
    const USER_KEY = "lg.jwt.user";

    // Where to reach the ML auth endpoint. Mirrors the API_BASE convention in
    // app.js so a dashboard served from a non-default origin can override via
    // window.LATENTGUARD_API.
    const API_BASE = window.LATENTGUARD_API || "http://localhost:8000";

    function save(token, exp, user) {
        try {
            localStorage.setItem(TOKEN_KEY, token);
            localStorage.setItem(EXP_KEY, String(exp || 0));
            if (user) localStorage.setItem(USER_KEY, user);
        } catch { /* private mode etc -- ignore */ }
    }
    function clear() {
        try {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(EXP_KEY);
            localStorage.removeItem(USER_KEY);
        } catch { /* */ }
    }
    function token() {
        try { return localStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
    }
    function user() {
        try { return localStorage.getItem(USER_KEY) || ""; } catch { return ""; }
    }
    function expired() {
        try {
            const exp = Number(localStorage.getItem(EXP_KEY) || "0");
            // 30s leeway -- treat almost-expired tokens as expired so a slow
            // dashboard tick doesn't get an avoidable 401.
            return exp > 0 && exp * 1000 < Date.now() + 30_000;
        } catch { return false; }
    }

    // Send the user to the login page. Preserves where they were so post-login
    // can bounce back (path passed via the 'next' query string).
    function redirectToLogin() {
        const next = encodeURIComponent(location.pathname + location.search + location.hash);
        location.replace(`login.html?next=${next}`);
    }

    // Guard for any page that requires auth (index.html calls this first).
    // Returns true if we let the page continue rendering; false means we've
    // already started a redirect and the caller should bail out.
    function requireAuth() {
        if (!token() || expired()) {
            redirectToLogin();
            return false;
        }
        return true;
    }

    // Wrapped fetch that attaches the bearer token and auto-logouts on 401.
    async function authFetch(url, init) {
        init = init || {};
        const headers = new Headers(init.headers || {});
        const t = token();
        if (t) headers.set("Authorization", `Bearer ${t}`);
        init.headers = headers;
        const res = await fetch(url, init);
        if (res.status === 401) {
            // Token rejected -- nuke local state and bounce to login.
            clear();
            redirectToLogin();
            // Throw so the caller's await doesn't try to consume the body.
            throw new Error("unauthenticated");
        }
        return res;
    }

    // POST credentials to /api/auth/login. Returns the parsed response on
    // 200, throws on anything else. Caller (login page) handles the throw.
    async function login(username, password) {
        const res = await fetch(`${API_BASE}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });
        if (!res.ok) {
            const body = await res.text();
            throw new Error(`HTTP ${res.status}: ${body.slice(0, 200) || "login failed"}`);
        }
        const data = await res.json();
        save(data.token, data.expires_at, data.user);
        return data;
    }

    function logout() {
        clear();
        redirectToLogin();
    }

    return { API_BASE, token, user, expired, requireAuth, authFetch, login, logout };
})();
